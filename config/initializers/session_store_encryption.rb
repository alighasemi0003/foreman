# frozen_string_literal: true

# F-015: encrypt ActiveRecord session payloads at rest (authenticated encryption).
# Must run after secret_token / secret_key_base is available.
require 'active_record/session_store'
require 'foreman/session_store/encrypted_marshal_serializer'

ActiveSupport.on_load(:active_record) do
  ActiveRecord::SessionStore::Session.serializer =
    Foreman::SessionStore::EncryptedMarshalSerializer
end

# Ensure the class is loaded even when ActiveRecord already loaded.
if defined?(ActiveRecord::SessionStore::Session)
  ActiveRecord::SessionStore::Session.serializer =
    Foreman::SessionStore::EncryptedMarshalSerializer
end
