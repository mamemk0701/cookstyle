# frozen_string_literal: true

module RuboCop
  module Cop
    module Custom
      class OutdatedPackageCheck < Base
        # Détection des packages avec leurs versions dans le cookbook
        def_node_matcher :package_with_version?, <<~PATTERN
          (block
            (send nil? :package (str $_))
            (args)
            (begin <(send nil? :version (str $_)) ...>)
          )
        PATTERN

        # Liste des dernières versions connues des logiciels
        LATEST_VERSIONS = {
          'nginx' => '1.26.3',
          'apache' => '2.4.57',
          'mysql' => '8.0.4',
        }.freeze

        def on_block(node)
          # On récupère tous les blocs de package dans le fichier
          package_name, package_version = package_with_version?(node)
          puts "Detected block package: #{package_name}, version: #{package_version}" if package_name && package_version

          return unless package_name && package_version

          # Si la version est 'latest', on ne fait pas de comparaison, mais on signale un False Positive
          if package_version == 'latest'
            add_offense(node,
                        message: "#{package_name} version is 'latest'. Security Smell: False Positive (Correct, but may trigger outdated check).")
            return
          end

          # On vérifie si le package a une version et s'il est obsolète
          if LATEST_VERSIONS.key?(package_name) && version_outdated?(package_version, LATEST_VERSIONS[package_name])
            add_offense(node,
                        message: "#{package_name} version #{package_version} is outdated. Latest: #{LATEST_VERSIONS[package_name]}.")
          end
        end

        private

        # Comparaison des versions
        def version_outdated?(current_version, latest_version)
          # Si la version la plus récente est 'latest', on ne la compare pas
          return false if latest_version == 'latest'

          Gem::Version.new(current_version) < Gem::Version.new(latest_version)
        end
      end
    end
  end
end
