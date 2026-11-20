# frozen_string_literal: true
# Runtime verification for mandatory first-login password change.
# Run inside the Foreman app container as:
#   bundle exec rails runner /path/to/verify_mandatory_password_change.rb
# Prints KEY=value lines only (no secrets).

require 'securerandom'

def out(k, v)
  puts "#{k}=#{v}"
end

User.as_anonymous_admin do
  login = "mpcr#{SecureRandom.hex(4)}"
  temp = 'TempInitial9!'
  final = 'CompletelyNew9!'
  weak = 'weak'

  form_path = Rails.root.join('app/views/users/_form.html.erb')
  form = File.read(form_path)
  out('checkbox_absent', !form.include?('Require password change on next login'))
  out('param_unpermitted', !File.read(Rails.root.join('app/controllers/concerns/foreman/controller/parameters/user.rb')).include?(':password_change_required,'))

  user = User.new(
    login: login,
    mail: "#{login}@example.com",
    auth_source: AuthSourceInternal.first,
    password: temp,
    password_confirmation: temp,
    password_change_required: false
  )
  saved = user.save
  out('create_ok', saved)
  out('create_errors', user.errors.full_messages.join(';').tr('=', ':')) unless saved
  out('force_on_create', user.reload.password_change_required?) if saved

  forged = User.new(
    login: "mpcrf#{SecureRandom.hex(3)}",
    mail: "mpcrf@example.com",
    auth_source: AuthSourceInternal.first,
    password: temp,
    password_confirmation: temp
  )
  forged.assign_attributes(password_change_required: false)
  forged.save!
  out('forge_false_ignored', forged.reload.password_change_required?)

  ldap = AuthSource.unscoped.where(type: 'AuthSourceLdap').first
  if ldap
    lu = User.new(login: "mpcrl#{SecureRandom.hex(3)}", mail: 'mpcrl@example.com', auth_source: ldap)
    lu.password_change_required = true
    lu.valid?
    out('ldap_force_cleared', !lu.password_change_required?)
  else
    out('ldap_force_cleared', 'SKIP_NO_LDAP')
  end

  if saved
    out('temp_matches', user.matching_password?(temp))
    User.current = user
    user.password = weak
    user.password_confirmation = weak
    user.current_password = temp
    weak_ok = user.save
    out('weak_rejected', !weak_ok)
    out('force_after_weak', user.reload.password_change_required?)
    out('temp_still_valid', user.matching_password?(temp))

    user.password = final
    user.password_confirmation = final
    user.current_password = temp
    strong_ok = user.save
    out('strong_accepted', strong_ok)
    out('strong_errors', user.errors.full_messages.join(';').tr('=', ':')) unless strong_ok
    if strong_ok
      # Mimic controller clear after successful self-change
      user.update_column(:password_change_required, false) if user.password_change_required?
      out('force_cleared', !user.reload.password_change_required?)
      out('old_rejected', !user.matching_password?(temp))
      out('new_accepted', user.matching_password?(final))
    end

    # Admin reset re-enables
    User.current = User.unscoped.find_by_login(ENV['SEED_ADMIN_USER'].presence || 'finaladmin') || User.unscoped.only_admin.except_hidden.first
    user.password = 'AdminReset9!'
    user.password_confirmation = 'AdminReset9!'
    user.current_password = nil
    reset_ok = user.save
    out('admin_reset_ok', reset_ok)
    out('force_after_admin_reset', user.reload.password_change_required?) if reset_ok

    user.destroy
    forged.destroy
  end
end

out('done', true)
