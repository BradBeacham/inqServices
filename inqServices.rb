#!/usr/bin/env ruby
# Brad Beacham 2018
#
#####################################################################################
# INFORMATION
# https://beacham.online/
#
# THIS SCRIPT IS NOT YET CAPABLE OF DEALING WITH SUBNETS.
# This functinoality will most likley be implemented in the future.  For now, just list individual hosts.
#
### TODO
#   - Determine an appropriate method of dealing with subnets.  Initial scans work fine, but detailed scans targeted at
#     specific ports will not work.
#       + Will most likley require additional threading and performing multiple scans at once, effectivly loosing any efficiency built into nmap.
#
#####################################################################################

#####################################################################################
# Required Gems:
require 'optparse'
require 'pathname'
require 'thread'
require 'thwait'
require 'nmap/parser'
# gem install nmap-parser
require 'nokogiri'
# gem install nokogiri
# require "celluloid"
# gem install celluloid
require 'highline/import'
# gem install highline -v 1.7.8

#####################################################################################
# Script switches section
$options = {}

ARGV << '-h' if ARGV.empty?

OptionParser.accept(Pathname) do |pn|
  begin
    Pathname.new(pn) if pn
    # code to verify existence
  rescue ArgumentError
    raise OptionParser::InvalidArgument, s
  end
end
 
optparse = OptionParser.new do|opts|
  # Set a banner, displayed at the top
  # of the help screen.
  opts.banner = "Usage: inqServices.rb"

   # Define the $options, and what they do
  $options[:directory] = false
   opts.on( '-d', '--output-dir <FILE>',Pathname, 'Specify the directory to save all output' ) do|file|
     $options[:directory] = file
   end
 
  $options[:host] = nil
  opts.on( '-i <HOST>', 'Specify individual host to perform enumeration against' ) do|input|
    $options[:host] = input
  end
 
  $options[:inputList] = nil
  opts.on( '-l', '--input-list <FILE>',Pathname, 'File containing one host per line to read from (NO SUBNETS!!!!)' ) do|file|
    $options[:inputList] = File.absolute_path(file)
  end

  $options[:threads] = 1
  opts.on( '-t [1-10]', '--threads [1-10]',Integer, 'Specify the number of concurrent scans to perform') do|int|
    if int > 0 && int < 11
      $options[:threads] = int
    elsif int > 10
      $options[:threads] = 10
    else
      $options[:threads] = 1
    end
  end

  $options[:noColour] = false
  opts.on( '--no-colour', 'Removes colourisation from the ourput' ) do
    $options[:noColour] = true
  end
 
   # This displays the help screen, all programs are assumed to have this option.
  opts.on( '-h', '--help', 'Display this screen' ) do
    puts "inqServices, the ruby based enumeration script!"
    puts "This tool is a wrapper for various other tools included within Kali linux.  This will streamline enumeration and help you on your way to getting mad $hellz"
    puts
    puts opts
    puts
    exit
  end 
end.parse!

#####################################################################################
# Appends notifications to the start of text (ie. [*], [+], etc)
class String
  if $options[:noColour]
    def error;        "[!] #{self}" end
    def fail;         "[-] #{self}" end
    def success;      "[+] #{self}" end
    def event;        "[*] #{self}" end
    def debug;        "[%] #{self}" end
    def notification; "[-] #{self}" end
  else
      def error;        "\e[31m[!]\e[0m #{self}" end        # [!] Red
      def fail;         "\e[31m[-]\e[0m #{self}" end		  # [-] Red
      def success;      "\e[32m[+]\e[0m #{self}" end        # [+] Green
      def event;        "\e[34m[*]\e[0m #{self}" end        # [*] Blue
      def debug;        "\e[35m[%]\e[0m #{self}" end        # [%] Magenta
      def notification; "[-] #{self}" end                   # [-]
  end
 end

 # Input validation on user input
 if $options[:host].to_s.empty? && $options[:inputList].to_s.empty?
  puts "ERROR: Please select host (-i) or input file (-l/--input-list)".error
  abort()
end 

if $options[:host] && $options[:inputList]
  puts "ERROR: Please choose only host (-i) or input file (-l/--input-list)".error
  abort()
end 

$threads = $options[:threads]

# Setup the directories depending on user input
# Expected structure:
#   <baseDir>/<host>/
#                   |-- initialTCP_<host>
#                   |-- initialUDP_<host>
#                   |-- allPortsTCP_<host>
#                   |-- initialTCP_Comprehensive_<host>
#                   |-- allPortsTCP_Comprehensive_<host>
directory = nil
if !$options[:directory]
  $directory = Dir.pwd
else
  $directory = $options[:directory]
end

#####################################################################################
# Setup the hosts to scan.
if $options[:inputList]
  $input = File.readlines("#{$options[:inputList]}")
  $input = $input.collect{|x| x.strip || x }
else
  $input = Array.new
  $input.push $options[:host]
end

#####################################################################################
# Thread pool function
class ThreadPool
  def initialize(max_threads = 10)
    @pool = SizedQueue.new(max_threads)
    max_threads.times{ @pool << 1 }
    @mutex = Mutex.new
    @running_threads = []

  end

  def run(&block)
    @pool.pop
    @mutex.synchronize do
      @running_threads << Thread.start do

        begin
          block[]

        rescue Exception => e
          puts "Exception: #{e.message}\n#{e.backtrace}"

        ensure
          @pool << 1

        end
      end
    end
  end

  def await_completion
    @running_threads.each &:join

  end
end

#####################################################################################
#
class NmapScan

  def initialize(input)
    # Setup instance variables
    # @input will still contain "/" characters nessecary to tell nmap to scan a subnet
    @input = input
    # @inputAlt replaces "/" for "-"
    if input.include? '/'
      @inputAlt = input.sub '/', '-'
    else
      @inputAlt = input
    end
    
    @baseDir = "#{$directory}/#{@inputAlt}"
    @scanType = ["initialTCP", "initialUDP", "allPortsTCP", "initialTCP_Comprehensive", "allPortsTCP_Comprehensive"]
    @scanLocation = Hash.new

    if File.exists?(@baseDir)
      confirm = ask("[Warning]: Directory [#{@baseDir}] exists!\n".error + "Do you want to continue [Y] or exit [N]?".error) { |yn| yn.limit = 1, yn.validate = /[yn]/i }
      exit unless confirm.downcase == 'y'
    else
      puts "Creating #{@baseDir}".notification
      Dir.mkdir(@baseDir)
    end

    @scanType.each_with_index do |type, index|
      @scanLocation["#{type}"] = "#{@baseDir}/#{@scanType[index]}_#{@inputAlt}"     
    end
    
  end

  def initialTCP()
    scanTypeNum = 0
    statsEvery = 300
    puts "Commencing #{@scanType[scanTypeNum]} scan against [#{@input}]".notification
    output = @scanLocation[@scanType[scanTypeNum]]
    options = ["-sS", "-F"]
    options = options.join(" ")  
    
    system("nmap #{options} -v --stats-every #{statsEvery} -oA #{output} #{@input} > #{output}.log")
    puts "#{@scanType[scanTypeNum]} scan against [#{@input}] complete!".success  
    return true
  end

  def initialUDP()
    scanTypeNum = 1
    statsEvery = 300
    puts "Commencing #{@scanType[scanTypeNum]} scan against [#{@input}]".notification
    output = @scanLocation[@scanType[scanTypeNum]]
    options = ["-sU", "-sV", "--version-all"]
    options = options.join(" ")  
    
    system("nmap #{options} -v --stats-every #{statsEvery} -oA #{output} #{@input} > #{output}.log")
    puts "#{@scanType[scanTypeNum]} scan against [#{@input}] complete!".success  
    return true
  end

  def allPortsTCP()
    scanTypeNum = 2
    statsEvery = 300
    puts "Commencing #{@scanType[scanTypeNum]} scan against [#{@input}]".notification
    output = @scanLocation[@scanType[scanTypeNum]]
    options = ["-sS", "-p -"]
    options = options.join(" ")  
    
    system("nmap #{options} -v --stats-every #{statsEvery} -oA #{output} #{@input} > #{output}.log")
    puts "#{@scanType[scanTypeNum]} scan against [#{@input}] complete!".success  
    return true
  end

  def initialTCP_C()
    scanTypeNum = 3
    statsEvery = 300
    output = @scanLocation[@scanType[scanTypeNum]]
    # Load the xml file from the initialTCP scan (type 0)
    portFile = @scanLocation[@scanType[0]]+".xml"

    # Determine open ports
    ports = Array.new
    parser = Nmap::Parser.parsefile(portFile)
    parser.hosts("up") do |host|
      [:tcp].each do |type|
        host.getports(type, "open") do |port|
          ports.push(port.num)
        end
      end
    end
    ports = ports.sort
    discoveredPorts = ports.join(",")

    # Configure and perform the scan  
    puts "Commencing #{@scanType[scanTypeNum]} scan against [#{@input}]".notification
    options = ["-sS", "-A", "--version-all","-p #{discoveredPorts}", "--script=default,discovery,safe,vuln"]
    options = options.join(" ")
    
    system("nmap #{options} -v --stats-every #{statsEvery} -oA #{output} #{@input} > #{output}.log")
    puts "#{@scanType[scanTypeNum]} scan against [#{@input}] complete!".success  
    return true
  end

  def allPortsTCP_C()
    scanTypeNum = 4
    statsEvery = 300
    output = @scanLocation[@scanType[scanTypeNum]]
    # Load the xml file from the allPortsTCP scan (type 2)
    portFile = @scanLocation[@scanType[2]]+".xml"

    # Determine open ports
    ports = Array.new
    parser = Nmap::Parser.parsefile(portFile)
    parser.hosts("up") do |host|
      [:tcp].each do |type|
        host.getports(type, "open") do |port|
          ports.push(port.num)
        end
      end
    end
    ports = ports.sort
    discoveredPorts = ports.join(",")

    puts "Commencing #{@scanType[scanTypeNum]} scan against [#{@input}]".notification
    options = ["-sS", "-A", "--version-all","-p #{discoveredPorts}", "--script=default,discovery,safe,vuln"]
    options = options.join(" ")  
    
    system("nmap #{options} -v --stats-every #{statsEvery} -oA #{output} #{@input} > #{output}.log")
    puts "#{@scanType[scanTypeNum]} scan against [#{@input}] complete!".success  
    return true
  end

  # For lack of a better way, use these functions to return the base filename and location of each scan file
  def initialTCP_location
    @scanLocation[@scanType[0]]
  end

  def initialUDP_location
    @scanLocation[@scanType[1]]
  end

  def allPortsTCP_location
    @scanLocation[@scanType[2]]
  end

  def initialTCP_C_location
    @scanLocation[@scanType[3]]
  end

  def allPortsTCP_C_location
      @scanLocation[@scanType[4]]
  end
 
end

def scan(input)
  # Performs a scan for a single host or subnet, depending what is passed via input.
  puts "Commencing scan against [#{input}]".event
  puts ""

  scan = NmapScan.new(input)

  threads = []
  # UDP Thread
  threads << Thread.new {scan.initialUDP}

  # TCP Thread
  threads << Thread.new {
    scan.initialTCP
    
    initialTCPThreads = []
    initialTCPThreads << Thread.new {scan.initialTCP_C}
    initialTCPThreads << Thread.new {
      scan.allPortsTCP
      scan.allPortsTCP_C
    }
    ThreadsWait.all_waits(*initialTCPThreads)
  }
  ThreadsWait.all_waits(*threads)
 
  # Trivial to add this infomration for <input> into a database for reference later.
  #puts scan.initialTCP_location.debug
  #puts scan.initialUDP_location.debug
  #puts scan.allPortsTCP_location.debug
  #puts scan.initialTCP_C_location.debug
  #puts scan.allPortsTCP_C_location.debug

  puts "Nmap scans completed for [#{input}]".success
  puts ""

end

#####################################################################################
# Main program Start

begin
  puts "#######################################################".event	
  pool = ThreadPool.new $threads

  $input.each do |host|
    pool.run{
      scan(host)
    }     

  end

  pool.await_completion

rescue SystemExit, Interrupt
	puts "[Ctrl + C] caught! Exiting".error
	abort()
end
