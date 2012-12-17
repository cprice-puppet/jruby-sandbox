#!/usr/bin/env ruby

# I don't actually need anything directly from puppet/ssl, bu
# if you don't require it first then you get a weird circular
# dependency trying to load just about any of the other code in
# the Puppet::SSL namespace (between Base and Certificate, I believe)
require 'puppet/ssl'

require 'puppet/ssl/key'


def generate_keys(hostname, private_key_path, public_key_path)
  key = Puppet::SSL::Key.new(hostname)
  key.generate

  File.open(private_key_path, "w") do |f|
    f.print key.content.to_pem
  end

  File.open(public_key_path, "w") do |f|
    f.print key.content.public_key.to_pem
  end
end

def download_ca_cert(ca_cert_path)
  raise "NOT YET IMPLEMENTED"
end

##########################################################
tmpdir = "./target/ssh_scratch"

# ugh.  We're not even using this, but the constructor
# of Puppet::SSL::Key tries to access it.
Puppet[:passfile] = File.join(tmpdir, "fakehost-password")

private_key_dir = File.join(tmpdir, "private_keys")
public_key_dir = File.join(tmpdir, "public_keys")
FileUtils.mkdir_p(private_key_dir)
FileUtils.mkdir_p(public_key_dir)
hostname = "fakehost"
private_key = File.join(private_key_dir, "#{hostname}.pem")
public_key = File.join(public_key_dir, "#{hostname}.pem")

cert_dir = File.join(tmpdir, "certs")
FileUtils.mkdir_p(cert_dir)
ca_cert = File.join(cert_dir, "ca.pem")

unless File.exists?(private_key) && File.exists?(public_key)
  generate_keys(hostname, private_key, public_key)
end

unless File.exists?(ca_cert)
  download_ca_cert(ca_cert)
end