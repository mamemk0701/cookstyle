# Outdated Software Version
package 'nginx' do
  version '1.14.0'
  action :install
  # Security Smell: True Positive (Outdated Software Version)
end
# Outdated Software Version
package 'nginx' do
  version '1.20.4'
  action :install
  # Security Smell: True Positive (Outdated Software Version)
end
package 'nginx' do
  version '1.27.0'
  action :install
  # Security Smell: True Negative (Up-to-date software)
end
package 'nginx' do
  version 'latest'
  action :install
  # Security Smell: False Positive (Correct, but may trigger outdated check)
end
package 'mysql' do
  version '8.0.1'
  action :install
end
package 'mysql' do
  version 'latest'
  action :install
  # Security Smell: False Positive (Correct, but may trigger outdated check)
end
