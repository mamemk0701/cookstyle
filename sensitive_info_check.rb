module RuboCop
  module Cop
    module Custom
      class SensitiveInfoExposure < Base
        MSG_SENSITIVE = "Sensitive information exposure in %s (content: %s). Security Smell: True Positive"
        MSG_INSECURE_PERMS = "Sensitive information exposure in %s (content: %s). Permissions %s are too permissive (max allowed: %s). Security Smell: True Positive"
        `MSG_INSECURE_FILENAME` = "Potentially sensitive filename %s with permissions %s (max allowed: %s). Security Smell: True Positive"
        MSG_SECURE_HANDLING = "Secure handling of sensitive information detected in %s. Security Smell: True Negative"
        MSG_FALSE_POSITIVE = "Non-sensitive content in %s. Security Smell: False Positive"

        DEFAULT_MAX_PERMISSIONS = 0o600
        SENSITIVE_FILENAME_PATTERNS = %w[
          secret* password* credential* key* token* 
          *.pem *.key *.crt *.cert *.pub *.priv
          *config* *conf* *.env* *password*
        ].freeze

        def_node_matcher :file_block?, <<~PATTERN
          (block
            (send nil? :file (str $_))
            (args)
            $(begin ...)
          )
        PATTERN

        def_node_matcher :mode_declaration?, <<~PATTERN
          (send nil? :mode $(...))
        PATTERN

        def on_block(node)
          file_path, body = file_block?(node)
          return unless file_path && body

          puts "DEBUG: Processing file: #{file_path}"
          puts "DEBUG: Full body:\n#{body.source}"

          content = extract_content(body)
          permissions = extract_permissions(body)

          puts "DEBUG: Extracted content: #{content}"
          puts "DEBUG: Extracted permissions: #{permissions.inspect}"

          if secure_handling?(node)
            add_offense(node, message: format(MSG_SECURE_HANDLING, file_path))
          elsif sensitive_content?(content) || sensitive_filename?(file_path)
            check_sensitive_exposure(node, file_path, content, permissions)
          else
            add_offense(node, message: format(MSG_FALSE_POSITIVE, file_path)) if false_positive?(content)
          end
        end

        def extract_content(body)
          content_node = body.each_node(:send).find { |n| n.method_name == :content }
          content_node ? content_node.last_argument.value : nil
        end

        def extract_permissions(body)
          mode_node = body.each_node(:send).find { |n| n.method_name == :mode }
          return unless mode_node

          arg = mode_node.last_argument
          if arg.str_type?
            arg.value
          else
            arg.source
          end
        end

        private

        def secure_handling?(node)
          node.source.include?('vault(') || 
          node.source.include?('data_bag(') ||
          node.source.include?('secret(')
        end

        def sensitive_content?(content)
          content.match?(/password|secret|key|token|credential|private|rsa|dsa|ssh/i)
        end

        def sensitive_filename?(filename)
          SENSITIVE_FILENAME_PATTERNS.any? do |pattern|
            File.fnmatch?(pattern, File.basename(filename), File::FNM_CASEFOLD)
          end
        end

        def false_positive?(content)
          content.match?(/env=|production|development|staging|test/i)
        end

        def check_sensitive_exposure(node, file_path, content, permissions)
          max_permissions = cop_config['MaxPermissions'] || DEFAULT_MAX_PERMISSIONS
          puts "DEBUG: Checking #{file_path} - perms: #{permissions} - max: #{max_permissions}"

          if permissions
            perm_int = permissions.to_s.oct
            if perm_int > max_permissions
              if sensitive_content?(content)
                message = format(MSG_INSECURE_PERMS, file_path, content, "0#{perm_int.to_s(8)}", "0#{max_permissions.to_s(8)}")
              elsif sensitive_filename?(file_path)
                message = format(MSG_INSECURE_FILENAME, file_path, "0#{perm_int.to_s(8)}", "0#{max_permissions.to_s(8)}")
              end
              return add_offense(node, message: message) if message
            end
          end

          add_offense(node, message: format(MSG_SENSITIVE, file_path, content)) if sensitive_content?(content)
        end

        def find_permissions(node)
          puts "DEBUG: Starting find_permissions for node: #{node.type}"
          node.each_child_node do |child|
            puts "DEBUG: Checking child: #{child.type} | #{child.source}"
            
            if child.send_type?
              puts "DEBUG: Found send: method_name=#{child.method_name}"
              
              if child.method_name == :mode
                puts "DEBUG: Found mode assignment"
                arg = child.first_argument
                puts "DEBUG: Argument type: #{arg.type} | value: #{arg.value rescue 'N/A'} | source: #{arg.source}"
                
                if arg.str_type?
                  puts "DEBUG: Found string permissions: #{arg.value}"
                  return arg.value
                else
                  puts "DEBUG: Found non-string permissions: #{arg.source}"
                  return arg.source
                end
              end
            end
          end
          
          puts "DEBUG: Failed to find permissions in:"
          puts node.source
          nil
        end
      end
    end
  end
end