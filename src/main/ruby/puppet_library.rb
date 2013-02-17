require 'puppet'
require 'puppet/file_serving/metadata'
require 'java'

class PuppetLibrary
  include Java::com.puppetlabs.sandbox.PuppetLibrary

  def initialize()
    Puppet.initialize_settings()
  end

  def findNode(node_name)
    Puppet::Node.indirection.find(node_name).to_pson
  end

  def saveReport(node_name, report_body)
    report = Puppet::Transaction::Report.convert_from(:yaml, report_body)
    result = Puppet::Transaction::Report.indirection.save(report, node_name)
    result.to_yaml
  end

  def searchFileMetadata(path)
    result = Puppet::FileServing::Metadata.indirection.search(path, nil)

    #if result.nil?
    #  return do_exception(response, "Could not find instances in #{indirection_name} with '#{key}'", 404)
    #end

    #format = format_to_use(request)
    #set_content_type(response, format)
    #
    #set_response(response, model.render_multiple(format, result))

    result.to_pson
  end

  def findFileMetadata(path)
    Puppet::FileServing::Metadata.indirection.find(path).to_pson
  end

  def findCatalog(node)
    Puppet::Resource::Catalog.indirection.find(node).to_pson
  end
end
