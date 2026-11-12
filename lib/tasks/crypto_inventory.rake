# frozen_string_literal: true

require 'openssl'

namespace :security do
  desc 'F-024: print cryptographic inventory and OpenSSL/FIPS provider state (read-only)'
  task crypto_inventory: :environment do
    require 'foreman/crypto_inventory'
    report = Foreman::CryptoInventory.report
    puts JSON.pretty_generate(report)
  end

  desc 'F-024: isolated OpenSSL FIPS-provider probe in a subprocess (does NOT enable host FIPS)'
  task crypto_fips_probe: :environment do
    require 'foreman/crypto_inventory'
    report = Foreman::CryptoInventory.isolated_fips_provider_probe
    puts JSON.pretty_generate(report)
  end
end
