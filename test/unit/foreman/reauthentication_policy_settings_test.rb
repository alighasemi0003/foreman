# frozen_string_literal: true

require 'test_helper'

class Foreman::ReauthenticationPolicySettingsTest < ActiveSupport::TestCase
  test 'mandatory settings reject disable via setting registry' do
    Foreman::Reauthentication::MANDATORY_SETTING_NAMES.each do |name|
      assert_raises(Foreman::SettingValueException) do
        Foreman.settings.set_user_value(name, false)
      end
      assert_equal true, Setting[name]
    end
  end

  test 'presenter marks mandatory settings readonly' do
    name = Foreman::Reauthentication::MANDATORY_SETTING_NAMES.first
    presenter = Foreman.settings.find(name)
    assert presenter.readonly?, name
  end

  test 'configurable setting is not readonly' do
    presenter = Foreman.settings.find('require_reauth_users_impersonate')
    refute presenter.readonly?
  end

  test 'settings category label is registered' do
    assert_equal N_('Re-authentication policy'),
                 Foreman::SettingManager.categories['reauthentication']
  end
end
