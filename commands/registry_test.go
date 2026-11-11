package commands

import (
	"bytes"
	"flag"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type paramsSeen struct {
	Verbose bool
	Wait    time.Duration
}

// paramRegistry holds one command with a bool flag and a duration flag, and reports
// what the command saw when it ran.
func paramRegistry(t *testing.T) (*Registry, *[]paramsSeen) {
	t.Helper()

	var seen []paramsSeen
	r := New()
	r.Register(&Command{
		Name:             "set",
		ShortDescription: "sets things",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := paramsSeen{}
			fl.BoolVar(&s.Verbose, "verbose", false, "say more")
			fl.DurationVar(&s.Wait, "wait", 0, "how long")
			return fl, &s
		},
		Run: func(fs any, a []string) (Result, error) {
			seen = append(seen, *fs.(*paramsSeen))
			return Value("ok"), nil
		},
	})

	return r, &seen
}

// TestInvokeReportsParametersInNameOrder pins deterministic errors for an unordered
// parameter object.
func TestInvokeReportsParametersInNameOrder(t *testing.T) {
	r, _ := paramRegistry(t)

	cases := map[string]struct {
		params map[string]string
		want   string
	}{
		"two unknown":               {map[string]string{"zed": "1", "alpha": "1"}, `set has no parameter "alpha"`},
		"unknown before bad bool":   {map[string]string{"aaa": "1", "verbose": "maybe"}, `set has no parameter "aaa"`},
		"bad bool before unknown":   {map[string]string{"verbose": "maybe", "zzz": "1"}, `verbose: expected a boolean, got "maybe"`},
		"bad value before bad bool": {map[string]string{"wait": "soon", "verbose": "maybe"}, `verbose: expected a boolean`},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			for i := 0; i < 50; i++ {
				_, err := Invoke(Request{Command: r.Get("set"), Params: tc.params})
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.want)
			}
		})
	}
}

func TestInvokeWithABadParameterSetsNothing(t *testing.T) {
	r, seen := paramRegistry(t)

	_, err := Invoke(Request{Command: r.Get("set"), Params: map[string]string{"verbose": "true", "wait": "soon"}})
	require.ErrorContains(t, err, "wait:")
	assert.Empty(t, *seen)

	v, err := Invoke(Request{Command: r.Get("set")})
	require.NoError(t, err)
	assert.Equal(t, "ok", v.Value)
	require.Len(t, *seen, 1)
	assert.Equal(t, paramsSeen{}, (*seen)[0])

	_, err = Invoke(Request{Command: r.Get("set"), Params: map[string]string{"verbose": "true", "wait": "2s"}})
	require.NoError(t, err)
	require.Len(t, *seen, 2)
	assert.Equal(t, paramsSeen{Verbose: true, Wait: 2 * time.Second}, (*seen)[1])
}

func TestRegisterRejectsReservedFlags(t *testing.T) {
	for _, name := range []string{"json", "pretty", "h", "help", "config", "socket"} {
		t.Run(name, func(t *testing.T) {
			r := New()
			assert.PanicsWithValue(t, "commands: clash declares reserved flag -"+name, func() {
				r.Register(&Command{
					Name: "clash",
					Flags: func() (*flag.FlagSet, any) {
						fl := flag.NewFlagSet("clash", flag.ContinueOnError)
						fl.Bool(name, false, "")
						return fl, nil
					},
					Run: func(fs any, a []string) (Result, error) { return Nothing(), nil },
				})
			})
		})
	}
}

// TestRegistryIsSafeForConcurrentUse exercises reads while commands are registered.
func TestRegistryIsSafeForConcurrentUse(t *testing.T) {
	r := New()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				r.Register(&Command{
					Name:             Name("late-" + strings.Repeat("a", i) + "-" + strings.Repeat("b", j)),
					ShortDescription: "registered after the surface started",
					Run:              func(fs any, a []string) (Result, error) { return Nothing(), nil },
				})
			}
		}(i)
	}

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = r.Get("help")
				_ = r.Schema()
			}
		}()
	}

	wg.Wait()

	var late int
	for _, c := range r.All() {
		if strings.HasPrefix(string(c.Name), "late-") {
			late++
		}
	}
	assert.Equal(t, 8*50, late)
}

func TestWriteCommandHelp(t *testing.T) {
	cs := CommandSchema{
		Name:  "change-remote",
		Short: "changes a remote",
		Help:  "Give it an address.",
		Flags: []FlagSchema{
			{Name: "address", Usage: "the new remote", Default: "1.2.3.4:4242"},
			{Name: "by-index", Bool: true, Usage: "match by index"},
			{Name: "json", Bool: true, Usage: "outputs as json"},
		},
	}

	out := &bytes.Buffer{}
	require.NoError(t, WriteCommandHelp(cs, out))

	assert.Equal(t, "change-remote - changes a remote\n"+
		"  Give it an address.\n"+
		"  -address string\n    \tthe new remote (default 1.2.3.4:4242)\n"+
		"  -by-index\n    \tmatch by index\n"+
		"  -json\n    \toutputs as json\n", out.String())
}
