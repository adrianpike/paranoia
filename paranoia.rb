require 'formatador'
require 'openssl'
require 'ostruct'

class ParseError < StandardError; end

class Cert < OpenStruct
  def self.initialize_from_string(string)
    name = nil; sig = nil

    string.each_line do |line|
      if line.match(/"alis"<.+>=(?:0x[0-9A-F]+\W+)?"(.*)"$/) then
        name = $1
      end

      if line.match(/"hpky"<.*>=(0x[0-9A-F]+)/) then
        sig = $1
      end
    end

    if name and sig then
      self.new(name: name, sig: sig)
    else
      # We throw exceptions here because we'd rather report as a bug and fix it
      # than continue in an undefined state - and possibly miss a sketchy cert.
      raise ParseError, "Incomplete signature given in cert: \"#{string}\""
    end
  end
end

class Keychain
  attr_accessor :certs, :parsed, :digest, :path

  def initialize(path = '/System/Library/Keychains/SystemRootCertificates.keychain')
    self.certs = []
    self.path = path
    self.parsed = false
    self.digest = OpenSSL::Digest::SHA256.new
  end

  def cert_data
    `security dump-keychain #{path}`
  end

  def parse
    buffer = ''
    cert_data.each_line do |line|
      if line.match(/^keychain:/) and buffer.length > 0 then
        cert = Cert.initialize_from_string(buffer)

        digest << cert.name
        digest << cert.sig
        certs << cert

        buffer = ''
     end
      buffer += line
    end
    parsed = true
  end

  def cert_hashes
    parse unless parsed

    certs.collect do |cert|
      {name: cert.name, signature: cert.sig}
    end
  end

end

os_data = `sw_vers`
os, version, build_version = os_data.split("\n").collect do |line|
  line.split(':').last.strip
end

system_keychain = Keychain.new

Formatador.display_line "[green] ** System Keychain ** [/]"
Formatador.display_compact_table(system_keychain.cert_hashes)

Formatador.display_line "[red]#{"=" * 80}[/]"
Formatador.display_line "#{os} #{version} [green]#{build_version}[/]"
Formatador.display_line "Your System Keychain digest is: [green]#{system_keychain.digest}[/]"
Formatador.display_line "[red]#{"=" * 80}[/]"
