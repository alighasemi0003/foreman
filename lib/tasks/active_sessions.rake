require 'active_record/session_store/session'

namespace :users do
  desc 'Clear active session flags for users without a non-expired Rails session'
  task :clear_stale_active_sessions => :environment do
    cutoff = Setting[:idle_timeout].minutes.ago
    active_user_ids = ActiveRecord::SessionStore::Session.where('updated_at >= ?', cutoff).find_each.filter_map do |stored_session|
      stored_session.data.with_indifferent_access[:user]
    rescue
      nil
    end

    User.unscoped.where(:has_active_session => true).where.not(:id => active_user_ids).update_all(:has_active_session => false)
  end
end
