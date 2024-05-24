package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	doStuff("/tmp/workspace/appscode/static-assets")
}

func doStuff(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filename := filepath.Join(dir, entry.Name())
		fmt.Println(filename)

		//data, err := os.ReadFile(filename)
		//if err != nil {
		//	return err
		//}
		//fmt.Println()

		// io.Copy()
	}
	return nil
}

func copyFile(dst, src string) (int64, error) {
	srcStats, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !srcStats.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer dstFile.Close()

	return io.Copy(dstFile, srcFile)
}
