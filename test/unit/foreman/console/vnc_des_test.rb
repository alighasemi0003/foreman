# frozen_string_literal: true

require 'test_helper'
require 'foreman/console/vnc_des'

class ForemanConsoleVncDesTest < ActiveSupport::TestCase
  test 'encrypts 16-byte challenge with DES bit-reversed key' do
    challenge = ('A'..'P').to_a.join.b
    out = Foreman::Console::VncDes.encrypt('secret', challenge)
    assert_equal 16, out.bytesize
    # Stable vector: same inputs → same ciphertext
    assert_equal out, Foreman::Console::VncDes.encrypt('secret', challenge)
    refute_equal out, Foreman::Console::VncDes.encrypt('other', challenge)
  end

  test 'rejects wrong challenge size' do
    assert_raises(ArgumentError) { Foreman::Console::VncDes.encrypt('x', 'short') }
  end
end
