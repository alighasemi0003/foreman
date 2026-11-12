# frozen_string_literal: true

require 'test_helper'

class UserLoginEventTest < ActiveSupport::TestCase
  include ActiveSupport::Testing::TimeHelpers

  setup do
    @user = FactoryBot.create(:user)
    Setting[:login_history_limit] = 3
  end

  test 'record_successful_login! creates one event with metadata' do
    assert_difference -> { UserLoginEvent.count }, 1 do
      event = UserLoginEvent.record_successful_login!(
        user: @user,
        remote_ip: '203.0.113.10',
        request_host: 'foreman.example.com',
        auth_method: 'password',
        auth_source_name: 'Internal'
      )
      assert_equal @user.id, event.user_id
      assert_equal '203.0.113.10', event.remote_ip
      assert_equal 'foreman.example.com', event.request_host
      assert_equal 'password', event.auth_method
      assert_equal 'Internal', event.auth_source_name
      assert event.logged_in_at.present?
      assert_operator event.logged_in_at, :<=, Time.now.utc + 1
    end
  end

  test 'multiple logins are ordered recent first' do
    t1 = UserLoginEvent.record_successful_login!(user: @user, remote_ip: '203.0.113.1')
    travel 2.seconds
    t2 = UserLoginEvent.record_successful_login!(user: @user, remote_ip: '203.0.113.2')
    ids = @user.login_events.recent_first.pluck(:id)
    assert_equal [t2.id, t1.id], ids.first(2)
  end

  test 'retention deletes oldest per user only' do
    other = FactoryBot.create(:user)
    UserLoginEvent.record_successful_login!(user: other, remote_ip: '198.51.100.1')

    4.times do |i|
      UserLoginEvent.record_successful_login!(user: @user, remote_ip: "203.0.113.#{i}")
    end

    assert_equal 3, @user.login_events.count
    assert_equal 1, other.login_events.count
    refute_includes @user.login_events.pluck(:remote_ip), '203.0.113.0'
  end

  test 'does not store password-like fields' do
    event = UserLoginEvent.record_successful_login!(
      user: @user,
      remote_ip: '203.0.113.9',
      auth_method: 'password'
    )
    attrs = event.attributes
    %w[password password_hash token session cookie authorization].each do |forbidden|
      refute attrs.key?(forbidden)
      refute attrs.values.any? { |v| v.to_s.downcase.include?('secretpass') }
    end
  end

  test 'user isolation via association' do
    other = FactoryBot.create(:user)
    UserLoginEvent.record_successful_login!(user: @user, remote_ip: '203.0.113.1')
    UserLoginEvent.record_successful_login!(user: other, remote_ip: '198.51.100.2')
    assert_equal ['203.0.113.1'], @user.login_events.pluck(:remote_ip)
    assert_equal ['198.51.100.2'], other.login_events.pluck(:remote_ip)
  end

  test 'concurrent inserts still respect retention ceiling' do
    threads = 5.times.map do |i|
      Thread.new do
        UserLoginEvent.record_successful_login!(user: @user, remote_ip: "203.0.113.#{i}")
      end
    end
    threads.each(&:join)
    assert_operator @user.login_events.count, :<=, UserLoginEvent.retention_limit
  end
end
