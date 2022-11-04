package testing

import (
	"io"
	"os"
	"testing"
)

func TestData(t *testing.T, fileName string, data string, generate bool) string {
	t.Helper()
	path := "testdata/" + fileName + ".json"

	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	defer f.Close()
	if err != nil {
		t.Fatalf("Error open a file %s: %s", path, err)
	}

	if generate {
		_, err := f.WriteString(data)
		if err != nil {
			t.Fatalf("Error writing to file %s: %s", path, err)
		}

		return data
	}

	fileBytes, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("Error read file %s: %s", path, err)
	}
	return string(fileBytes)
}
