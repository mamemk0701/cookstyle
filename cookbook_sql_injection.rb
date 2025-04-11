# frozen_string_literal: true

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
