require 'cbor'

# Each example selects one of the schema's independent top-level rules.
ENV['CDDL_UNUSED_OK'] = '1'
require 'cddl'

# cddl 0.12.14 mutates string literals while parsing rules and building diagnostics.
Warning.singleton_class.prepend(Module.new do
  def warn(message, **options)
    return if message.match?(%r{/cddl-0\.12\.14/lib/cddl\.rb:\d+: warning: literal string will be frozen in the future\b})

    super
  end
end)

describe 'Secure RSMP v1 CDDL' do
  def schema_for(rule)
    source = File.read(File.expand_path('../schemas/secure/rsmp-secure-v1.cddl', __dir__))
    CDDL::Parser.new("root = #{rule}\n#{source}")
  end

  it 'accepts the four encoded application payload examples from section 8.1' do
    schema = schema_for('rsmp-payload')
    %w[a1617601 a16176f93c00 a16176f98000 a1617663312e30].each do |hex|
      payload = CBOR.decode([hex].pack('H*'))
      expect(schema.validate(payload)).to be_truthy
    end
  end

  it 'requires a top-level object and JSON-compatible values at every depth' do
    schema = schema_for('rsmp-payload')
    expect(schema.validate({'values' => [true, nil, {'id' => -1}]})).to be_truthy
    expect(schema.validate([], false)).to be_falsey
    expect(schema.validate({'values' => [{1 => 'id'}]}, false)).to be_falsey
    expect(schema.validate({'values' => ['binary'.b]}, false)).to be_falsey
  end

  it 'requires the exact EDHOC frame fields and a byte-string message' do
    schema = schema_for('secure-message')
    frame = {'v' => 1, 'type' => 'edhoc', 'profile' => 'rsmp-secure-v1', 'msg' => 1, 'edhoc' => 'abc'.b}
    expect(schema.validate(frame)).to be_truthy
    expect(schema.validate(frame.except('profile'), false)).to be_falsey
    expect(schema.validate(frame.merge('extra' => 1), false)).to be_falsey
    expect(schema.validate(frame.merge('edhoc' => 'abc'), false)).to be_falsey
  end

  it 'checks the embedded COSE protected header and Partial IV in a data frame' do
    schema = schema_for('data-frame')
    enc = [CBOR.encode({1 => 24}), {6 => "\x01".b}, 'ciphertext'.b]
    frame = {'v' => 1, 'type' => 'data', 'epoch' => 0, 'enc' => enc}
    expect(schema.validate(frame)).to be_truthy
    wrong_algorithm = [CBOR.encode({1 => 1}), enc[1], enc[2]]
    expect(schema.validate(frame.merge('enc' => wrong_algorithm), false)).to be_falsey
    long_iv = [enc[0], {6 => "\x01".b * 5}, enc[2]]
    expect(schema.validate(frame.merge('enc' => long_iv), false)).to be_falsey
  end

  it 'allows EDHOC bytes in a rekey message and rejects them in a rekey acknowledgement' do
    schema = schema_for('rekey-plaintext')
    ack = {'kind' => 'rekey_ack', 'next_epoch' => 1}
    message = ack.merge('kind' => 'rekey_msg1', 'edhoc' => 'abc'.b)
    expect(schema.validate(ack)).to be_truthy
    expect(schema.validate(message)).to be_truthy
    expect(schema.validate(ack.merge('edhoc' => 'abc'.b), false)).to be_falsey
  end
end
