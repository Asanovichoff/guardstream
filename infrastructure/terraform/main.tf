###############################################################################
# GuardStream — AWS Infrastructure
#
# Services deployed:
#   Amazon MSK          — Managed Kafka (replaces local Kafka container)
#   Amazon ElastiCache  — Managed Redis (replaces local Redis container)
#   Amazon ECS/Fargate  — Container orchestration for all 4 services
#   Amazon ECR          — Private container image registry
#   Amazon S3           — Permanent alert archive (beyond Redis 24h TTL)
#   Amazon SNS          — Attack notifications → email / Slack / PagerDuty
#   Amazon CloudWatch   — Metrics, logs, and alarms
#   Amazon RDS Aurora   — Persistent block history (survives Redis restarts)
#   AWS ALB             — Load balancer in front of the demo API
#   AWS Secrets Manager — Secure credential storage
#   Amazon VPC          — Network isolation
#   AWS IAM             — Least-privilege roles for each service
#
# Usage:
#   terraform init
#   terraform plan -var="db_password=<password>"
#   terraform apply -var="db_password=<password>"
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region"   { default = "us-east-1" }
variable "db_password"  { sensitive = true }
variable "alert_email"  { default = "" }

locals {
  name = "guardstream"
  tags = { Project = "GuardStream", ManagedBy = "Terraform" }
}

###############################################################################
# VPC — isolated network for all GuardStream resources
###############################################################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = local.name
  cidr = "10.0.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = true

  tags = local.tags
}

###############################################################################
# ECR — container image registry for ECS task definitions
###############################################################################

resource "aws_ecr_repository" "demo" {
  name                 = "${local.name}/demo"
  image_tag_mutability = "MUTABLE"
  tags                 = local.tags
}

resource "aws_ecr_repository" "ai_consumer" {
  name                 = "${local.name}/ai-consumer"
  image_tag_mutability = "MUTABLE"
  tags                 = local.tags
}

resource "aws_ecr_repository" "stats_consumer" {
  name                 = "${local.name}/stats-consumer"
  image_tag_mutability = "MUTABLE"
  tags                 = local.tags
}

resource "aws_ecr_repository" "dashboard" {
  name                 = "${local.name}/dashboard"
  image_tag_mutability = "MUTABLE"
  tags                 = local.tags
}

###############################################################################
# Amazon MSK — Managed Kafka (KRaft mode, no Zookeeper)
# Replaces the local Apache Kafka container. Same API — zero code changes.
###############################################################################

resource "aws_msk_cluster" "main" {
  cluster_name           = local.name
  kafka_version          = "3.7.x.kraft"
  number_of_broker_nodes = 2

  broker_node_group_info {
    instance_type   = "kafka.t3.small"
    client_subnets  = module.vpc.private_subnets
    security_groups = [aws_security_group.msk.id]

    storage_info {
      ebs_storage_info { volume_size = 20 }
    }
  }

  encryption_info {
    encryption_in_transit { client_broker = "TLS" }
  }

  logging {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.msk.name
      }
    }
  }

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "msk" {
  name              = "/guardstream/msk"
  retention_in_days = 7
  tags              = local.tags
}

resource "aws_security_group" "msk" {
  name   = "${local.name}-msk"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port       = 9094
    to_port         = 9094
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_tasks.id]
  }

  tags = local.tags
}

###############################################################################
# Amazon ElastiCache — Managed Redis
# Replaces the local Redis container. Multi-AZ, automatic failover.
###############################################################################

resource "aws_elasticache_subnet_group" "main" {
  name       = local.name
  subnet_ids = module.vpc.private_subnets
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id = local.name
  description          = "GuardStream fast-path enforcement and alert storage"

  node_type            = "cache.t4g.micro"
  num_cache_clusters   = 2
  automatic_failover_enabled = true

  engine_version       = "7.1"
  port                 = 6379
  subnet_group_name    = aws_elasticache_subnet_group.main.name
  security_group_ids   = [aws_security_group.redis.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis.name
    destination_type = "cloudwatch-logs"
    log_format       = "text"
    log_type         = "slow-log"
  }

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "redis" {
  name              = "/guardstream/redis"
  retention_in_days = 7
  tags              = local.tags
}

resource "aws_security_group" "redis" {
  name   = "${local.name}-redis"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_tasks.id]
  }

  tags = local.tags
}

###############################################################################
# Amazon RDS Aurora Serverless v2 — Persistent block history
# Redis restarts clear in-memory state. Aurora stores block history durably.
###############################################################################

resource "aws_db_subnet_group" "main" {
  name       = local.name
  subnet_ids = module.vpc.private_subnets
  tags       = local.tags
}

resource "aws_rds_cluster" "main" {
  cluster_identifier     = local.name
  engine                 = "aurora-postgresql"
  engine_mode            = "provisioned"
  engine_version         = "15.4"
  database_name          = "guardstream"
  master_username        = "gsadmin"
  master_password        = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  serverlessv2_scaling_configuration {
    min_capacity = 0.5
    max_capacity = 4
  }

  skip_final_snapshot = true
  tags                = local.tags
}

resource "aws_rds_cluster_instance" "main" {
  identifier         = "${local.name}-instance"
  cluster_identifier = aws_rds_cluster.main.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.main.engine
  engine_version     = aws_rds_cluster.main.engine_version
  tags               = local.tags
}

resource "aws_security_group" "rds" {
  name   = "${local.name}-rds"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_tasks.id]
  }

  tags = local.tags
}

###############################################################################
# Amazon S3 — Permanent alert archive
# Redis alerts expire after 24h. S3 keeps them for 90 days.
###############################################################################

resource "aws_s3_bucket" "alerts" {
  bucket = "${local.name}-alerts-${data.aws_caller_identity.current.account_id}"
  tags   = local.tags
}

resource "aws_s3_bucket_versioning" "alerts" {
  bucket = aws_s3_bucket.alerts.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "alerts" {
  bucket = aws_s3_bucket.alerts.id
  rule {
    id     = "expire-old-alerts"
    status = "Enabled"
    filter { prefix = "alerts/" }
    expiration { days = 90 }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alerts" {
  bucket = aws_s3_bucket.alerts.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "alerts" {
  bucket                  = aws_s3_bucket.alerts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

###############################################################################
# Amazon SNS — Attack notifications
###############################################################################

resource "aws_sns_topic" "attacks" {
  name = "${local.name}-attacks"
  tags = local.tags
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.attacks.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

###############################################################################
# Amazon CloudWatch — Metrics, logs, alarms
###############################################################################

resource "aws_cloudwatch_log_group" "ai_consumer" {
  name              = "/guardstream/ai-consumer"
  retention_in_days = 14
  tags              = local.tags
}

resource "aws_cloudwatch_log_group" "demo" {
  name              = "/guardstream/demo"
  retention_in_days = 7
  tags              = local.tags
}

resource "aws_cloudwatch_metric_alarm" "high_block_rate" {
  alarm_name          = "${local.name}-high-block-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "IPsBlocked"
  namespace           = "GuardStream"
  period              = 60
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "More than 10 IPs blocked in the last 2 minutes — active attack"
  alarm_actions       = [aws_sns_topic.attacks.arn]
  tags                = local.tags
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = local.name
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          title   = "Events Processed per Batch"
          metrics = [["GuardStream", "EventsProcessed"]]
          period  = 30
          stat    = "Sum"
        }
      },
      {
        type = "metric"
        properties = {
          title   = "IPs Blocked"
          metrics = [["GuardStream", "IPsBlocked"]]
          period  = 60
          stat    = "Sum"
        }
      },
      {
        type = "metric"
        properties = {
          title   = "Attack Patterns Detected"
          metrics = [["GuardStream", "PatternsDetected"]]
          period  = 60
          stat    = "Sum"
        }
      },
    ]
  })
}

###############################################################################
# AWS Secrets Manager — Secure credential storage
###############################################################################

resource "aws_secretsmanager_secret" "guardstream" {
  name        = "${local.name}/config"
  description = "GuardStream service credentials"
  tags        = local.tags
}

resource "aws_secretsmanager_secret_version" "guardstream" {
  secret_id = aws_secretsmanager_secret.guardstream.id
  secret_string = jsonencode({
    redis_url        = "rediss://${aws_elasticache_replication_group.main.primary_endpoint_address}:6379"
    kafka_bootstrap  = aws_msk_cluster.main.bootstrap_brokers_tls
    s3_bucket        = aws_s3_bucket.alerts.bucket
    sns_topic_arn    = aws_sns_topic.attacks.arn
    db_host          = aws_rds_cluster.main.endpoint
  })
}

###############################################################################
# IAM — Least-privilege role for ECS tasks
###############################################################################

resource "aws_iam_role" "ecs_task" {
  name = "${local.name}-ecs-task"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "ecs_task" {
  name = "${local.name}-ecs-task-policy"
  role = aws_iam_role.ecs_task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3AlertArchive"
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.alerts.arn}/alerts/*"
      },
      {
        Sid    = "SNSPublish"
        Effect = "Allow"
        Action = ["sns:Publish"]
        Resource = aws_sns_topic.attacks.arn
      },
      {
        Sid    = "CloudWatchMetrics"
        Effect = "Allow"
        Action = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = { "cloudwatch:namespace" = "GuardStream" }
        }
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:log-group:/guardstream/*"
      },
      {
        Sid    = "SecretsManager"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.guardstream.arn
      },
    ]
  })
}

###############################################################################
# Application Load Balancer — in front of the demo API
###############################################################################

resource "aws_lb" "demo" {
  name               = "${local.name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = module.vpc.public_subnets
  tags               = local.tags
}

resource "aws_lb_target_group" "demo" {
  name        = "${local.name}-demo"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = module.vpc.vpc_id
  target_type = "ip"

  health_check {
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = local.tags
}

resource "aws_lb_listener" "demo" {
  load_balancer_arn = aws_lb.demo.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.demo.arn
  }
}

resource "aws_security_group" "alb" {
  name   = "${local.name}-alb"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

###############################################################################
# Amazon ECS + Fargate — container orchestration
###############################################################################

resource "aws_ecs_cluster" "main" {
  name = local.name
  configuration {
    execute_command_configuration {
      logging = "DEFAULT"
    }
  }
  tags = local.tags
}

resource "aws_security_group" "ecs_tasks" {
  name   = "${local.name}-ecs-tasks"
  vpc_id = module.vpc.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

resource "aws_ecs_task_definition" "ai_consumer" {
  family                   = "${local.name}-ai-consumer"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  task_role_arn            = aws_iam_role.ecs_task.arn
  execution_role_arn       = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name  = "ai-consumer"
    image = "${aws_ecr_repository.ai_consumer.repository_url}:latest"
    environment = [
      { name = "AI_BATCH_SIZE",     value = "50" },
      { name = "AI_BATCH_INTERVAL", value = "30" },
      { name = "BLOCK_TTL_SECONDS", value = "3600" },
      { name = "AWS_REGION",        value = var.aws_region },
      { name = "CW_NAMESPACE",      value = "GuardStream" },
    ]
    secrets = [
      { name = "REDIS_URL",       valueFrom = "${aws_secretsmanager_secret.guardstream.arn}:redis_url::" },
      { name = "KAFKA_BOOTSTRAP_SERVERS", valueFrom = "${aws_secretsmanager_secret.guardstream.arn}:kafka_bootstrap::" },
      { name = "S3_BUCKET",       valueFrom = "${aws_secretsmanager_secret.guardstream.arn}:s3_bucket::" },
      { name = "SNS_TOPIC_ARN",   valueFrom = "${aws_secretsmanager_secret.guardstream.arn}:sns_topic_arn::" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.ai_consumer.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "ecs"
      }
    }
  }])

  tags = local.tags
}

resource "aws_ecs_service" "ai_consumer" {
  name            = "${local.name}-ai-consumer"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.ai_consumer.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = module.vpc.private_subnets
    security_groups = [aws_security_group.ecs_tasks.id]
  }

  tags = local.tags
}

###############################################################################
# Data sources
###############################################################################

data "aws_caller_identity" "current" {}

###############################################################################
# Outputs
###############################################################################

output "api_url" {
  value = "http://${aws_lb.demo.dns_name}"
}

output "msk_bootstrap" {
  value     = aws_msk_cluster.main.bootstrap_brokers_tls
  sensitive = true
}

output "redis_endpoint" {
  value = aws_elasticache_replication_group.main.primary_endpoint_address
}

output "s3_bucket" {
  value = aws_s3_bucket.alerts.bucket
}

output "sns_topic_arn" {
  value = aws_sns_topic.attacks.arn
}

output "ecr_repositories" {
  value = {
    demo          = aws_ecr_repository.demo.repository_url
    ai_consumer   = aws_ecr_repository.ai_consumer.repository_url
    stats_consumer = aws_ecr_repository.stats_consumer.repository_url
    dashboard     = aws_ecr_repository.dashboard.repository_url
  }
}
