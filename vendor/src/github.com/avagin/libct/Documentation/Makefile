ASCIIDOC	:= asciidoc
A2X		:= a2x
XMLTO		:= xmlto

SRC		+= libct.txt
MANS		:= $(patsubst %.txt,%.1,$(SRC))
PDFS		:= $(patsubst %.txt,%.pdf,$(SRC))

all: $(MANS)

%.1: %.txt
	$(E) "  GEN     " $@
	$(Q) $(ASCIIDOC) -b docbook -d manpage -o $(patsubst %.1,%.xml,$@) $<
	$(Q) $(XMLTO) man --skip-validation $(patsubst %.1,%.xml,$@) 2>/dev/null

all-pdfs: $(PDFS)

%.pdf: %.txt
	$(E) "  GEN     " $@
	$(Q) $(A2X) -fpdf -d manpage $^

clean:
	$(E) "  CLEANUP  docs"
	$(Q) rm -f ./*.xml
	$(Q) rm -f ./*.1
	$(Q) rm -f ./*.pdf
