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
