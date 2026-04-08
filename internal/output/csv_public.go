package output

// PrintCSVHeaderPublic exposes the CSV header for external callers
func (p *Printer) PrintCSVHeaderPublic() {
	p.printCSVHeader()
}
