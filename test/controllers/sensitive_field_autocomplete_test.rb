# frozen_string_literal: true

require 'test_helper'

class SensitiveFieldAutocompleteUsersControllerTest < ActionController::TestCase
  tests UsersController

  test 'edit self form current password has autocomplete off' do
    get :edit, params: { :id => users(:admin).id }, session: set_session_user
    assert_response :success
    assert_select 'input[type=password][name=?][autocomplete=?]', 'user[current_password]', 'off'
  end
end

class SensitiveFieldAutocompleteLdapControllerTest < ActionController::TestCase
  tests AuthSourceLdapsController

  test 'new LDAP form account password has autocomplete off' do
    get :new, session: set_session_user
    assert_response :success
    assert_select 'input[type=password][name=?][autocomplete=?]', 'auth_source_ldap[account_password]', 'off'
  end
end

class SensitiveFieldAutocompleteHttpProxyControllerTest < ActionController::TestCase
  tests HttpProxiesController

  test 'new HTTP proxy form password has autocomplete off' do
    get :new, session: set_session_user
    assert_response :success
    assert_select 'input[type=password][name=?][autocomplete=?]', 'http_proxy[password]', 'off'
  end
end

class SensitiveFieldAutocompleteHostgroupControllerTest < ActionController::TestCase
  tests HostgroupsController

  test 'new hostgroup root_pass has autocomplete off' do
    get :new, session: set_session_user
    assert_response :success
    assert_select 'input[type=password][name=?][autocomplete=?]', 'hostgroup[root_pass]', 'off'
  end
end
