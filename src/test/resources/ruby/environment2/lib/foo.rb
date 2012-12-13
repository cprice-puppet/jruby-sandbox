class Foo
  def initialize
    @var2 = 2
  end

  def loop
    5.times do
      puts "Hello from environment2 foo!"
      sleep 0.5
    end
    self
  end

  def printobject(other)
    puts "Printing an object from environment2."
    puts "\tMy class: #{self.class}"
    puts "\tMy instance vars: #{self.instance_variables}"
    puts "\tOther Class: #{other.class}"
    puts "\tOther Vars: #{other.instance_variables}"

    foo = Foo.new
    puts "Constructed a new Foo.  instance vars: '#{foo.instance_variables}'"
  end
end