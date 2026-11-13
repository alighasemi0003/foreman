# frozen_string_literal: true

namespace :security do
  desc 'F-039: fail if Ruby/ERB/source maps exist under public/ (web root)'
  task check_public_source_exposure: :environment do
    require 'json'
    require 'foreman/public_source_exposure'
    report = Foreman::PublicSourceExposure.report
    puts JSON.pretty_generate(report)
    abort('public web root contains source/debug artifacts') unless report[:ok]
  end
end
