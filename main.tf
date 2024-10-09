provider "aws" {
  region = "us-east-1"  # Cambia a la región que prefieras
}

# Crear una VPC con soporte DNS habilitado
resource "aws_default_vpc" "default_vpc"{
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "Default VPC"
  }
}

resource "tls_private_key" "ec2_key" {
    algorithm = "RSA"
    rsa_bits  = 2048
}

# Crear un par de claves para acceder a la instancia
resource "aws_key_pair" "devops_qa" {
  key_name   = "devops_qa"
  public_key = tls_private_key.ec2_key.public_key_openssh  # Ruta a tu clave pública
}

resource "local_file" "ssh_key" {
    filename = "devops_qa.pem"
    content  = tls_private_key.ec2_key.private_key_pem
}

# Seguridad del grupo (permitir SSH y HTTP)
resource "aws_security_group" "instance" {
  name        = "instance-sg"
  description = "Allow SSH and HTTP inbound traffic"
  vpc_id      = aws_default_vpc.default_vpc.id

  ingress {
    description = "ingress port"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "ingress selenium grid"
    from_port   = 4444
    to_port     = 4444
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "ingres prometheus"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "ingres pushgateway"
    from_port   = 9091
    to_port     = 9091
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "ingres grafana"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Selenium-Docker"
  }
}

data "aws_ami" "amazon-2" {
    most_recent = true

    filter {
        name = "name"
        values = ["amzn2-ami-hvm-*-x86_64-ebs"]
    }
    owners = ["amazon"]
}

# Crear una instancia EC2
resource "aws_instance" "selenium_instance" {
  ami           = data.aws_ami.amazon-2.id  # Amazon Linux 2 AMI
  instance_type = "t2.medium"
  key_name      = aws_key_pair.devops_qa.key_name
  vpc_security_group_ids = [aws_security_group.instance.id]
  
  metadata_options {
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "required" # IMDSv2 requerido
  }

  # Instalar Docker y ejecutar dos contenedores
  user_data     = file("install.sh")

  tags = {
    Name = "Selenium Docker"
  }

  provisioner "local-exec" {
    command = "sleep 300"
  }
}

# Salida de la dirección IP pública de la instancia
output "ssh-command" {
  value = "ssh -i devops_qa.pem ec2-user@${aws_instance.selenium_instance.public_dns}"
}

output "ip_public"{
  value = aws_instance.selenium_instance.public_ip
}