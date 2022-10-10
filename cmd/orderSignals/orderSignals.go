package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var sym = flag.String("sym", "", "path to sym file")
var signals = flag.String("signals", "", "coma delimited list of signals")

type listItem struct {
	value string
	order int64
}

func main() {
	flag.Parse()
	if *sym == "" {
		log.Fatal("sym file path is empty")
	}

	if *signals == "" {
		log.Fatal("signals is empty")
	}

	signalsN := strings.Split(*signals, ",")
	_ = signalsN

	var signalsRE []string
	for _, s := range signalsN {
		signalsRE = append(signalsRE, regexp.QuoteMeta(s))
	}

	re, err := regexp.Compile(
		fmt.Sprintf(`^(\d+),\d+,\d+,main.(%v)(\[\d+])?$`,
			strings.Join(signalsRE, "|")))
	if err != nil {
		panic(err)
	}

	f, err := os.Open(*sym)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	seenSignals := make(map[string]struct{})
	var items []listItem

	br := bufio.NewScanner(f)
	for br.Scan() {
		ln := br.Text()
		ss := re.FindStringSubmatch(ln)
		if ss == nil {
			continue
		}

		_, seen := seenSignals[ss[2]]
		if seen {
			continue
		}
		seenSignals[ss[2]] = struct{}{}

		item := listItem{value: ss[2]}
		item.order, err = strconv.ParseInt(ss[1], 10, 32)
		if err != nil {
			panic(err)
		}
		items = append(items, item)
	}

	if err := br.Err(); err != nil {
		panic(err)
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].order < items[j].order
	})

	for _, i := range items {
		fmt.Println(i.value)
	}
}
