module RuboCop
    module Cop
      module Custom
        class SensitiveInfoExposure < Base
          MSG_SENSITIVE = "Sensitive information exposure in %s (content: %s). Security Smell: True Positive"
          MSG_INSECURE_PERMS = "Sensitive information exposure in %s (content: %s). Permissions %s are too permissive. Security Smell: True Positive"
          MSG_SECURE_HANDLING = "Secure handling of sensitive information detected in %s. Security Smell: True Negative"
          MSG_FALSE_POSITIVE = "Non-sensitive content in %s. Security Smell: False Positive"
  
          # Détection des ressources file avec du contenu
          def_node_matcher :file_with_content?, <<~PATTERN
            (block
              (send nil? :file (str $_))
              (args)
              (begin
                <
                  (send nil? :content (str $_))
                  ...
                >
              )
            )
          PATTERN
  
          def on_block(node)
            file_path, content = file_with_content?(node)
            return unless file_path && content
  
            if secure_handling?(node)
              add_offense(node, message: format(MSG_SECURE_HANDLING, file_path))
            elsif sensitive_content?(content)
              check_sensitive_exposure(node, file_path, content)
            else
              add_offense(node, message: format(MSG_FALSE_POSITIVE, file_path)) if false_positive?(content)
            end
          end
  
          private
  
          def secure_handling?(node)
            node.source.include?('vault(') || 
            node.source.include?('data_bag(') ||
            node.source.include?('secret(')
          end
  
          def sensitive_content?(content)
            content.match?(/password|secret|key|token|credential/i)
          end
  
          def false_positive?(content)
            content.match?(/env=|production|development|staging/i)
          end
  
          def check_sensitive_exposure(node, file_path, content)
            permissions = find_permissions(node)
            
            if permissions && permissions.to_i(8) > 0o600
              add_offense(node, message: format(MSG_INSECURE_PERMS, file_path, content, permissions))
            else
              add_offense(node, message: format(MSG_SENSITIVE, file_path, content))
            end
          end
  
          def find_permissions(node)
            node.each_child_node do |child|
              if child.send_type? && child.method_name == :mode
                return child.first_argument.value
              end
            end
            nil
          end
        end
      end
    end
  end