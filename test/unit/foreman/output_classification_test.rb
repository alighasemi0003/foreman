# frozen_string_literal: true

require 'test_helper'

class Foreman::OutputClassificationTest < ActiveSupport::TestCase
  test 'levels are ordered and labeled' do
    assert_equal 'public', Foreman::OutputClassification.normalize('PUBLIC')
    assert_equal 'internal', Foreman::OutputClassification.normalize('unknown-level')
    assert_operator Foreman::OutputClassification.rank('restricted'),
                    :>, Foreman::OutputClassification.rank('confidential')
    assert_equal 'restricted',
                 Foreman::OutputClassification.highest('internal', 'restricted', 'confidential')
    assert_match(/Internal/i, Foreman::OutputClassification.label_for('internal'))
  end

  test 'kind mapping raises to restricted when secrets revealed' do
    assert_equal 'confidential', Foreman::OutputClassification.for_kind('host_enc', secrets_revealed: false)
    assert_equal 'restricted', Foreman::OutputClassification.for_kind('host_enc', secrets_revealed: true)
    assert_equal 'internal', Foreman::OutputClassification.for_kind('inventory_csv')
    assert_equal 'restricted', Foreman::OutputClassification.for_kind('key_pair_pem')
  end

  test 'apply_headers sets machine readable classification' do
    response = ActionDispatch::Response.new
    Foreman::OutputClassification.apply_headers!(response, 'confidential')
    assert_equal 'confidential', response.headers['X-Foreman-Classification']
    assert_match(/Confidential/i, response.headers['X-Foreman-Classification-Label'])
    assert_equal 'foreman-proposed-v1', response.headers['X-Foreman-Classification-Policy']
  end

  test 'yaml preamble is comments only and parseable with body' do
    preamble = Foreman::OutputClassification.yaml_preamble('confidential')
    assert_match(/\A#/, preamble)
    refute_match(/synth-secret/, preamble)
    doc = Foreman::OutputClassification.labeled_yaml({ 'a' => 1 }, 'confidential')
    parsed = YAML.safe_load(doc)
    assert_equal({ 'a' => 1 }, parsed)
    assert_includes doc, 'X-Foreman-Classification: confidential'
  end

  test 'print banner contains label without secrets' do
    text = Foreman::OutputClassification.print_banner_text('restricted')
    assert_match(/Classification:/i, text)
    assert_match(/Restricted/i, text)
  end

  test 'disabled setting skips headers' do
    Setting[:output_classification_enabled] = false
    response = ActionDispatch::Response.new
    Foreman::OutputClassification.apply_headers!(response, 'internal')
    assert_nil response.headers['X-Foreman-Classification']
  ensure
    Setting[:output_classification_enabled] = true
  end
end
