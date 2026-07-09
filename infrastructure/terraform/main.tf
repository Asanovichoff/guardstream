###############################################################################
# GuardStream — AWS Infrastructure
#
# Services deployed:
#   Amazon MSK          — Managed Kafka, 3 brokers across 3 AZs
#   Amazon ElastiCache  — Managed Redis, Multi-AZ with auto-failover
#   Amazon ECS/Fargate  — All 4 services: demo, ai-consumer, stats-consumer, dashboard
#   Amazon ECR          — Private container image registry
#   Amazon S3           — Permanent alert archive (90-day retention)
#   Amazon SNS          — Attack notifications → email / Slack / PagerDuty
#   Amazon CloudWatch   — Per-service log groups, custom metrics, alarms, dashboard
#   Amazon RDS Aurora   — Persistent block history (survives Redis restarts)
#   AWS ALB             — Public load balancer in front of the demo API
#   AWS WAF             — OWASP managed rules attached to ALB
#   AWS Secrets Manager — Credentials injected at task startup
#   Amazon VPC          — 3 AZs, public + private subnets, NAT gateway
#   AWS IAM             — Separate task role (runtime) and execution role (ECS plumbing)
#   AWS Auto Scaling    — CPU-based scaling for demo API and ai-consumer
#
# Usage:
#   terraform init
#   terraform plan  -var="db_password=<strong-password>"
#   terraform apply -var="db_password=<strong-password>"
#
# Optional — enable HTTPS (requires a domain you control):
#   terraform apply -var="db_password=..." -var="domain_name=api.example.com"
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

variable "aws_region"  { default = "us-east-1" }
variable "db_password" { sensitive = true }
variable "alert_email" { default = "" }
# Set to enable ACM certificate + HTTPS listener + HTTP→HTTPS redirect
variable "domain_name" { default = "" }

locals {
  name = "guardstream"
  tags = { Project = "GuardStream", ManagedBy = "Terraform" }
}

###############################################################################
# VPC — 3 AZs required for 3-broker MSK cluster (1 broker per AZ)
###############################################################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = local.name
  cidr = "10.0.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = true

  tags = local.tags
}

###############################################################################
# ECR — container image registry for all four ECS task definitions
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
# Amazon MSK — Managed Kafka (KRaft mode, 3 brokers × 3 AZs)
# 3 brokers = 1 per AZ. A 2-broker cluster loses quorum on any single AZ failure.
###############################################################################

resource "aws_msk_cluster" "main" {
  cluster_name           = local.name
  kafka_version          = "3.7.x.kraft"
  number_of_broker_nodes = 3

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
# Amazon ElastiCache — Managed Redis (Multi-AZ, TLS, automatic failover)
###############################################################################

resource "aws_elasticache_subnet_group" "main" {
  name       = local.name
  subnet_ids = module.vpc.private_subnets
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id       = local.name
  description                = "GuardStream fast-path enforcement and alert storage"
  node_type                  = "cache.t4g.micro"
  num_cache_clusters         = 2
  automatic_failover_enabled = true
  engine_version             = "7.1"
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.main.name
  security_group_ids         = [aws_security_group.redis.id]
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
# NOTE: skip_final_snapshot = true is intentional for this demo environment.
#       Set to false in production and provide a final_snapshot_identifier.
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
# Amazon S3 — Permanent alert archive (Redis TTL = 24h, S3 retention = 90 days)
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
# Amazon CloudWatch — One log group per service, alarms, dashboard
###############################################################################

resource "aws_cloudwatch_log_group" "ai_consumer" {
  name              = "/guardstream/ai-consumer"
  retention_in_days = 14
  tags              = local.tags
}

resource "aws_cloudwatch_log_group" "stats_consumer" {
  name              = "/guardstream/stats-consumer"
  retention_in_days = 7
  tags              = local.tags
}

resource "aws_cloudwatch_log_group" "demo" {
  name              = "/guardstream/demo"
  retention_in_days = 7
  tags              = local.tags
}

resource "aws_cloudwatch_log_group" "dashboard" {
  name              = "/guardstream/dashboard"
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
# AWS WAF — OWASP managed rules on the ALB
# Relevant since GuardStream is itself an attack-detection platform — it should
# practice what it preaches.
###############################################################################

resource "aws_wafv2_web_acl" "demo" {
  name  = local.name
  scope = "REGIONAL"

  default_action { allow {} }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-common-ruleset"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-waf"
    sampled_requests_enabled   = true
  }

  tags = local.tags
}

resource "aws_wafv2_web_acl_association" "demo" {
  resource_arn = aws_lb.demo.arn
  web_acl_arn  = aws_wafv2_web_acl.demo.arn
}

###############################################################################
# AWS Secrets Manager — Credentials injected at ECS task startup
###############################################################################

resource "aws_secretsmanager_secret" "guardstream" {
  name        = "${local.name}/config"
  description = "GuardStream service credentials and connection strings"
  tags        = local.tags
}

resource "aws_secretsmanager_secret_version" "guardstream" {
  secret_id = aws_secretsmanager_secret.guardstream.id
  secret_string = jsonencode({
    redis_url       = "rediss://${aws_elasticache_replication_group.main.primary_endpoint_address}:6379"
    kafka_bootstrap = aws_msk_cluster.main.bootstrap_brokers_tls
    s3_bucket       = aws_s3_bucket.alerts.bucket
    sns_topic_arn   = aws_sns_topic.attacks.arn
    db_host         = aws_rds_cluster.main.endpoint
    db_password     = var.db_password
  })
}

###############################################################################
# IAM — Two distinct roles:
#   ecs_task      — runtime permissions the application code actually uses
#   ecs_execution — ECS control-plane permissions (pull image, write logs, read secrets)
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
        Sid      = "S3AlertArchive"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.alerts.arn}/alerts/*"
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.attacks.arn
      },
      {
        Sid      = "CloudWatchMetrics"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = { "cloudwatch:namespace" = "GuardStream" }
        }
      },
      {
        Sid      = "CloudWatchLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:log-group:/guardstream/*"
      },
    ]
  })
}

# ECS execution role — used by the ECS control plane, not by application code
resource "aws_iam_role" "ecs_execution" {
  name = "${local.name}-ecs-execution"
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

# Grants: pull images from ECR, write logs to CloudWatch
resource "aws_iam_role_policy_attachment" "ecs_execution_managed" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Grants: read secrets so ECS can inject them as environment variables at startup
resource "aws_iam_role_policy" "ecs_execution_secrets" {
  name = "${local.name}-ecs-execution-secrets"
  role = aws_iam_role.ecs_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadSecrets"
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = aws_secretsmanager_secret.guardstream.arn
    }]
  })
}

###############################################################################
# Application Load Balancer — public-facing, WAF-protected, optional HTTPS
###############################################################################

resource "aws_security_group" "alb" {
  name   = "${local.name}-alb"
  vpc_id = module.vpc.vpc_id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
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

# HTTP listener: forward directly when no domain, redirect to HTTPS when domain is set
resource "aws_lb_listener" "http_forward" {
  count             = var.domain_name == "" ? 1 : 0
  load_balancer_arn = aws_lb.demo.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.demo.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  count             = var.domain_name != "" ? 1 : 0
  load_balancer_arn = aws_lb.demo.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# ACM certificate + HTTPS listener — only created when domain_name is provided
resource "aws_acm_certificate" "demo" {
  count             = var.domain_name != "" ? 1 : 0
  domain_name       = var.domain_name
  validation_method = "DNS"
  tags              = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_listener" "https" {
  count             = var.domain_name != "" ? 1 : 0
  load_balancer_arn = aws_lb.demo.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.demo[0].arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.demo.arn
  }
}

###############################################################################
# ECS — cluster, shared security group, and all four task definitions + services
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

  # ALB health checks and request forwarding reach containers on port 8000
  ingress {
    description     = "ALB to containers"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

# ── demo API ──────────────────────────────────────────────────────────────────

resource "aws_ecs_task_definition" "demo" {
  family                   = "${local.name}-demo"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  task_role_arn            = aws_iam_role.ecs_task.arn
  execution_role_arn       = aws_iam_role.ecs_execution.arn

  container_definitions = jsonencode([{
    name         = "demo"
    image        = "${aws_ecr_repository.demo.repository_url}:latest"
    portMappings = [{ containerPort = 8000, protocol = "tcp" }]
    secrets = [
      { name = "REDIS_URL",               valueFrom = "${aws_secretsmanager_secret.guardstream.arn}:redis_url::" },
      { name = "KAFKA_BOOTSTRAP_SERVERS", valueFrom = "${aws_secretsmanager_secret.guardstream.arn}:kafka_bootstrap::" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.demo.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "ecs"
      }
    }
  }])

  tags = local.tags
}

resource "aws_ecs_service" "demo" {
  name            = "${local.name}-demo"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.demo.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = module.vpc.private_subnets
    security_groups = [aws_security_group.ecs_tasks.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.demo.arn
    container_name   = "demo"
    container_port   = 8000
  }

  depends_on = [aws_lb_listener.http_forward, aws_lb_listener.http_redirect]

  tags = local.tags
}

# ── ai-consumer ──────────────────────────────────────────────────────────────

resource "aws_ecs_task_definition" "ai_consumer" {
  family                   = "${local.name}-ai-consumer"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  task_role_arn            = aws_iam_role.ecs_task.arn
  execution_role_arn       = aws_iam_role.ecs_execution.arn

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
      { name = "REDIS_URL",               valueFrom = "${aws_secretsmanager_secret.guardstream.arn}:redis_url::" },
      { name = "KAFKA_BOOTSTRAP_SERVERS", valueFrom = "${aws_secretsmanager_secret.guardstream.arn}:kafka_bootstrap::" },
      { name = "S3_BUCKET",               valueFrom = "${aws_secretsmanager_secret.guardstream.arn}:s3_bucket::" },
      { name = "SNS_TOPIC_ARN",           valueFrom = "${aws_secretsmanager_secret.guardstream.arn}:sns_topic_arn::" },
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

# ── stats-consumer ───────────────────────────────────────────────────────────

resource "aws_ecs_task_definition" "stats_consumer" {
  family                   = "${local.name}-stats-consumer"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  task_role_arn            = aws_iam_role.ecs_task.arn
  execution_role_arn       = aws_iam_role.ecs_execution.arn

  container_definitions = jsonencode([{
    name  = "stats-consumer"
    image = "${aws_ecr_repository.stats_consumer.repository_url}:latest"
    secrets = [
      { name = "REDIS_URL",               valueFrom = "${aws_secretsmanager_secret.guardstream.arn}:redis_url::" },
      { name = "KAFKA_BOOTSTRAP_SERVERS", valueFrom = "${aws_secretsmanager_secret.guardstream.arn}:kafka_bootstrap::" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.stats_consumer.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "ecs"
      }
    }
  }])

  tags = local.tags
}

resource "aws_ecs_service" "stats_consumer" {
  name            = "${local.name}-stats-consumer"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.stats_consumer.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = module.vpc.private_subnets
    security_groups = [aws_security_group.ecs_tasks.id]
  }

  tags = local.tags
}

# ── dashboard ─────────────────────────────────────────────────────────────────

resource "aws_ecs_task_definition" "dashboard" {
  family                   = "${local.name}-dashboard"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  task_role_arn            = aws_iam_role.ecs_task.arn
  execution_role_arn       = aws_iam_role.ecs_execution.arn

  container_definitions = jsonencode([{
    name         = "dashboard"
    image        = "${aws_ecr_repository.dashboard.repository_url}:latest"
    portMappings = [{ containerPort = 8000, protocol = "tcp" }]
    secrets = [
      { name = "REDIS_URL", valueFrom = "${aws_secretsmanager_secret.guardstream.arn}:redis_url::" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.dashboard.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "ecs"
      }
    }
  }])

  tags = local.tags
}

resource "aws_ecs_service" "dashboard" {
  name            = "${local.name}-dashboard"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.dashboard.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = module.vpc.private_subnets
    security_groups = [aws_security_group.ecs_tasks.id]
  }

  tags = local.tags
}

###############################################################################
# Application Auto Scaling — CPU-based scaling for demo API and ai-consumer
###############################################################################

resource "aws_appautoscaling_target" "demo" {
  max_capacity       = 10
  min_capacity       = 2
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.demo.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "demo_cpu" {
  name               = "${local.name}-demo-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.demo.resource_id
  scalable_dimension = aws_appautoscaling_target.demo.scalable_dimension
  service_namespace  = aws_appautoscaling_target.demo.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

resource "aws_appautoscaling_target" "ai_consumer" {
  max_capacity       = 10
  min_capacity       = 1
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.ai_consumer.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "ai_consumer_cpu" {
  name               = "${local.name}-ai-consumer-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ai_consumer.resource_id
  scalable_dimension = aws_appautoscaling_target.ai_consumer.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ai_consumer.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

###############################################################################
# Data sources
###############################################################################

data "aws_caller_identity" "current" {}

###############################################################################
# Outputs
###############################################################################

output "api_url" {
  value = var.domain_name != "" ? "https://${var.domain_name}" : "http://${aws_lb.demo.dns_name}"
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
    demo           = aws_ecr_repository.demo.repository_url
    ai_consumer    = aws_ecr_repository.ai_consumer.repository_url
    stats_consumer = aws_ecr_repository.stats_consumer.repository_url
    dashboard      = aws_ecr_repository.dashboard.repository_url
  }
}
