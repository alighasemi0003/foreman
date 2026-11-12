# frozen_string_literal: true

namespace :security do
  desc 'F-031: print security event taxonomy catalog (JSON)'
  task event_taxonomy: :environment do
    require 'json'
    catalog = Foreman::SecurityEvent::Taxonomy.catalog
    puts JSON.pretty_generate(
      policy: Foreman::SecurityEvent::Taxonomy.policy_id,
      categories: Foreman::SecurityEvent::Taxonomy.categories,
      classifications: Foreman::SecurityEvent::Taxonomy.classifications,
      events: catalog
    )
  end
end
