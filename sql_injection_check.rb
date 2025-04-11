module RuboCop
  module Cop
    module Custom
      class CodeInjectionRisk < Base
        MSG_SQL_INJECTION = 'Potential SQL injection in %s (content: %s). Security Smell: True Positive'
        MSG_CODE_INJECTION = 'Potential code injection in %s (content: %s). Security Smell: True Positive'
        MSG_SANITIZED_INPUT = 'Sanitized input detected in %s. Security Smell: False Positive'
        MSG_SAFE_CODE = 'No injection risk detected in %s. Security Smell: True Negative'

        SQL_INJECTION_PATTERNS = [
          /['"]\s*\+\s*[^;]+;/,             # Concatenation in string
          /['"]\s*{{\s*[^}]*\s*}}/,         # Jinja-style interpolation
          /['"]\s*<\s*%=?\s*[^%]*\s*%>/,    # ERB-style interpolation
          /\$\{[^}]+\}/, # Shell-style variable
          /['"]\s*\.format\([^)]*\)/, # String formatting
          /\bexec\s*\(/, # exec calls
          /\beval\s*\(/, # eval calls
        ].freeze

        SAFE_SQL_PATTERNS = [
          /\?/,                             # Prepared statement placeholder
          /%\([^)]+\)s/,                    # Named parameter
          /:[a-z0-9_]+/,                    # Parameter binding
          /\bprepare\b/i,                    # Prepared statement
        ].freeze

        def_node_matcher :file_with_content?, <<~PATTERN
            (block
              (send nil? :file (str $_))
              (args)
              (begin
                <
                  (send nil? :content $(...))
                  ...
                >
              )
            )
          PATTERN

        def on_block(node)
          file_path, content_node = file_with_content?(node)
          return unless file_path && content_node

          content = content_node.str_type? ? content_node.value : content_node.source

          if sql_injection_risk?(content)
            add_offense(node, message: format(MSG_SQL_INJECTION, file_path, content.strip))
          elsif code_injection_risk?(content)
            add_offense(node, message: format(MSG_CODE_INJECTION, file_path, content.strip))
          elsif sanitized_input?(content)
            add_offense(node, message: format(MSG_SANITIZED_INPUT, file_path))
          else
            add_offense(node, message: format(MSG_SAFE_CODE, file_path))
          end
        end

        private

        def sql_injection_risk?(content)
          return false unless content.match?(/SELECT|INSERT|UPDATE|DELETE|EXEC/i)

          SQL_INJECTION_PATTERNS.any? { |pattern| content.match?(pattern) } &&
            !SAFE_SQL_PATTERNS.any? { |pattern| content.match?(pattern) }
        end

        def code_injection_risk?(content)
          risky_patterns = [
            /\beval\(/,
            /\bexec\(/,
            /\bsystem\(/,
            /`[^`]+`/,
            /\$\{[^}]+\}/,
            /<\s*%=?\s*[^%]*\s*%>/,
          ]

          risky_patterns.any? { |pattern| content.match?(pattern) }
        end

        def sanitized_input?(content)
          SAFE_SQL_PATTERNS.any? { |pattern| content.match?(pattern) } ||
            content.match?(/escape\(|sanitize\(|quote\(/i)
        end
      end
    end
  end
end
