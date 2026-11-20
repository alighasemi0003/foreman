# calibrate default cost to be at least 50ms (performance-wise safe)
# Skip when the settings registry is not ready yet (e.g. first `db:seed`
# immediately after migrate, before auth settings DSL is loaded). A later
# seed/boot pass will calibrate once definitions exist.
unless Setting.respond_to?(:find) && (Setting.find('bcrypt_cost') rescue nil)
  Rails.logger.warn('Skipping bcrypt_cost calibration — setting definition not loaded yet')
  return
end

new_cost = BCrypt::Engine.calibrate(50)

# keep minimum reasonable cost in case CPU was busy
new_cost = 5 if new_cost < 5

# and set it if it's higher than current cost
current_cost = Setting[:bcrypt_cost]
if current_cost.nil? || current_cost < new_cost
  Setting[:bcrypt_cost] = new_cost
end
