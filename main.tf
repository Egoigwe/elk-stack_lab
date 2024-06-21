provider "aws" {
  region  = "eu-west-2"
  profile = "default"
}

# RSA key of size 4096 bits
resource "tls_private_key" "keypair-1" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# creating private key
resource "local_file" "keypair-1" {
  content         = tls_private_key.keypair-1.private_key_pem
  filename        = "elk.pem"
  file_permission = "600"
}

# creating an Ec2 keypair
resource "aws_key_pair" "keypair" {
  key_name   = "elk-keypair"
  public_key = tls_private_key.keypair-1.public_key_openssh
}

# creating Ec2 for elk Vault
resource "aws_instance" "elk_server" {
  ami                         = "ami-053a617c6207ecc7b" // ubuntu
  instance_type               = "t2.large"
  key_name                    = aws_key_pair.keypair.id
  vpc_security_group_ids      = [aws_security_group.elk_sg.id]
  associate_public_ip_address = true
  user_data                   = file("./scripts/installELK.sh")
  metadata_options {
    http_tokens = "required"
    http_endpoint = "enabled"
  }
  root_block_device {
    encrypted = true
  }
  tags = {
    Name = "elk-server"
  }
}

# Create a Null Resource and Provisioners
resource "null_resource" "my_null_resource" {
  depends_on = [ aws_instance.elk_server ]
  # Connection Block for Provisioners to connect to the EC2 Instance
  connection {
    host = aws_instance.elk_server.public_ip
    type = "ssh"
    user = "ubuntu"
    private_key = tls_private_key.keypair-1.private_key_pem
  }

  provisioner "file" {
    source = "scripts/elasticsearch.yml"
    destination = "/tmp/elasticsearch.yml"
  }

    provisioner "file" {
    source = "scripts/kibana.yml"
    destination = "/tmp/kibana.yml"
  }

    provisioner "file" {
    source = "scripts/apache-01.conf"
    destination = "/tmp/apache-01.conf"
  }
  
}

output "public-ip" {
  value = aws_instance.elk_server.public_ip
}

locals {
  ingress-config = [
    { descr = "Elasticsearch port", protocol = "tcp", from_port = 9200, to_port = 9200, cidr_blocks = ["0.0.0.0/0"] },
    { descr = "Logstash ports", protocol = "tcp", from_port = 5043, to_port = 5044, cidr_blocks = ["0.0.0.0/0"] },
    { descr = "Kibana port", protocol = "tcp", from_port = 5601, to_port = 5601, cidr_blocks = ["0.0.0.0/0"] },
    { descr = "Ssh port", protocol = "tcp", from_port = 22, to_port = 22, cidr_blocks = ["0.0.0.0/0"] },
  ]
}

resource "aws_security_group" "elk_sg" {
  name        = "elk_sg"
  description = "Allow all elasticsearch traffic"

  dynamic "ingress" {
    for_each = local.ingress-config
    content {
    description = ingress.value.descr
    from_port   = ingress.value.from_port
    to_port     = ingress.value.to_port
    protocol    = ingress.value.protocol
    cidr_blocks = ingress.value.cidr_blocks
    }
  }
# outbound
  egress {
    description = "Allow outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]

  }
  tags = {
    Name = "elk_sg"
  }
}
