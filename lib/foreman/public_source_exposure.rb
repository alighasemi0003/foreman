# frozen_string_literal: true

require 'find'

# F-039: reproducible checks that application source is not sitting in the
# public web root. Does not claim to hide source from container filesystem readers.
module Foreman
  module PublicSourceExposure
    FORBIDDEN_UNDER_PUBLIC = [
      /\.rb\z/i,
      /\.erb\z/i,
      /\.rake\z/i,
      /\.map\z/i,
      /\.map\.gz\z/i,
    ].freeze

    module_function

    def public_root
      Rails.root.join('public')
    end

    def scan(root: public_root)
      root = Pathname.new(root)
      findings = []
      return { ok: true, findings: [], root: root.to_s } unless root.directory?

      Find.find(root.to_s) do |path|
        next unless File.file?(path)
        next if File.symlink?(path)

        rel = Pathname.new(path).relative_path_from(root).to_s
        if FORBIDDEN_UNDER_PUBLIC.any? { |re| re.match?(File.basename(path)) }
          findings << rel
        end
      end

      { ok: findings.empty?, findings: findings, root: root.to_s }
    end

    def report
      result = scan
      result.merge(
        task: 'F-039',
        middleware: 'Foreman::Middleware::BlockSourceMaps',
        note: 'Absence of public source files ≠ source encryption. See docs/source-code-protection.md',
      )
    end
  end
end
