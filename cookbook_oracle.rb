# frozen_string_literal: true

# Cookbook:: security_smells
# Recipe:: default

# Outdated Software Version
package 'nginx' do
  version '1.14.0'
  action :install
  # Security Smell: True Positive (Outdated Software Version)
end

package 'nginx' do
  version 'latest'
  action :install
  # Security Smell: False Positive (Correct, but may trigger outdated check)
end

package 'nginx' do
  version '1.18.0'
  action :install
  # Security Smell: True Negative (Up-to-date software)
end

# Outdated Dependencies
package 'python' do
  version '2.7.18'
  action :install
  # Security Smell: True Positive (Outdated Dependency - Python)
end

package 'python' do
  version '3.9.7'
  action :install
  # Security Smell: False Positive (Not outdated but could be flagged)
end

package 'python' do
  version '3.10.4'
  action :install
  # Security Smell: True Negative (Secure dependency version)
end

# Sensitive Information Exposure
file '/tmp/secrets.txt' do
  content 'password=mysecretpassword'
  mode '0644'
  action :create
  # Security Smell: True Positive (Sensitive Information Exposure)
end

file '/tmp/env.txt' do
  content 'env=production'
  mode '0644'
  action :create
  # Security Smell: False Positive (Non-sensitive info but might be flagged)
end

file '/tmp/secrets.txt' do
  content "{{ vault('secret_password') }}"
  mode '0600'
  action :create
  # Security Smell: True Negative (Secure handling of sensitive information)
end

# Code Injection (SQL Injection)
file '/tmp/sql_query.py' do
  content <<~EOH
    query = "SELECT * FROM users WHERE name = '{{ user_input }}';"
  EOH
  action :create
  # Security Smell: True Positive (Code Injection - SQL Injection)
end

file '/tmp/sql_query.py' do
  content <<~EOH
    query = "SELECT * FROM users WHERE name = %(username)s;"
  EOH
  action :create
  # Security Smell: False Positive (Sanitized input, but could be flagged)
end

file '/tmp/sql_query.py' do
  content <<~EOH
    query = "SELECT * FROM users;"
  EOH
  action :create
  # Security Smell: True Negative (No user input or code injection risk)
end

# Insecure Dependency Management
remote_file '/tmp/package.tar.gz' do
  source 'http://untrusted-source.com/package.tar.gz'
  action :create
  # Security Smell: True Positive (Insecure Dependency Management)
end

remote_file '/tmp/package.tar.gz' do
  source 'https://trusted-source.com/package.tar.gz'
  action :create
  # Security Smell: False Positive (Secure, but flagged due to similarity)
end

remote_file '/tmp/package.tar.gz' do
  source 'https://verified-source.com/package.tar.gz'
  action :create
  # Security Smell: True Negative (Secure download source)
end

# Path Traversal
file '/tmp/file.txt' do
  content 'Path traversal vulnerability - unsanitized input'
  action :create
  # Security Smell: True Positive (Path Traversal)
end

file '/tmp/file.txt' do
  content 'Properly sanitized input for file path (False Positive)'
  action :create
  # Security Smell: False Positive (Safe path but might trigger traversal detection)
end

file '/tmp/file.txt' do
  content 'Static file path with no user input'
  action :create
  # Security Smell: True Negative (No risk of path traversal)
end

# Command Injection
execute 'execute_command' do
  command 'ls {{ user_input }}'
  action :run
  # Security Smell: True Positive (Command Injection)
end

execute 'static_command' do
  command 'ls /var/www'
  action :run
  # Security Smell: False Positive (No user input, safe command)
end

execute 'safe_command' do
  command 'ls /tmp'
  action :run
  # Security Smell: True Negative (Properly sanitized command, no injection risk)
end

# Insecure Input Handling
execute 'process_input' do
  command 'echo {{ user_input }}'
  action :run
  # Security Smell: True Positive (Insecure Input Handling - Unsanitized input)
end

execute 'static_input' do
  command 'echo "static_text"'
  action :run
  # Security Smell: False Positive (No dynamic input, but might be flagged)
end

execute 'sanitized_input' do
  command 'echo {{ validated_input }}'
  action :run
  # Security Smell: True Negative (Proper validation and sanitization)
end

# Insecure Configuration Management
file '/etc/nginx/sites-available/default' do
  content <<~EOH
    server {
      listen 80 default_server;
      root /var/www/html;
    }
  EOH
  action :create
  # Security Smell: True Positive (Insecure default configuration)
end

file '/etc/nginx/sites-available/default' do
  content <<~EOH
    server {
      listen 443 ssl;
      ssl_certificate /etc/ssl/certs/mycert.crt;
      root /var/www/html_secure;
    }
  EOH
  action :create
  # Security Smell: False Positive (Secure configuration, but may be flagged)
end

file '/etc/nginx/sites-available/secure' do
  content <<~EOH
    server {
      listen 443 ssl;
      ssl_certificate /etc/ssl/certs/mycert.crt;
      root /var/www/html_secure;
      ssl_protocols TLSv1.2 TLSv1.3;
    }
  EOH
  action :create
  # Security Smell: True Negative (Secure custom configuration)
end

# Inadequate Naming Conventions
ruby_block 'inadequate_naming' do
  block do
    'non_standard_variable_name'
  end
  action :run
  # Security Smell: True Positive (Inadequate Naming Convention)
end

ruby_block 'false_positive_naming' do
  block do
    ENV_VAR = 'production'
  end
  action :run
  # Security Smell: False Positive (Correct, but might trigger due to style)
end

ruby_block 'proper_naming' do
  block do
    'standard'
  end
  action :run
  # Security Smell: True Negative (Proper naming convention)
end
