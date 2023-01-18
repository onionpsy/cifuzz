package dialog

import (
	"os"
	"sort"

	"atomicgo.dev/keyboard/keys"
	"github.com/pkg/errors"
	"github.com/pterm/pterm"
	"golang.org/x/exp/maps"
	"golang.org/x/term"

	"code-intelligence.com/cifuzz/pkg/log"
)

// Select offers the user a list of items (label:value) to select from and returns the value of the selected item
func Select(message string, items map[string]string, sorted bool) (string, error) {
	options := maps.Keys(items)
	if sorted {
		sort.Strings(options)
	}
	prompt := pterm.DefaultInteractiveSelect.WithOptions(options)
	prompt.DefaultText = message

	result, err := prompt.Show()
	if err != nil {
		return "", errors.WithStack(err)
	}

	return items[result], nil
}

// MultiSelect offers the user a list of items (label:value) to select from and returns the values of the selected items
func MultiSelect(message string, items map[string]string) ([]string, error) {
	options := maps.Keys(items)
	sort.Strings(options)

	prompt := pterm.DefaultInteractiveMultiselect.WithOptions(options)
	prompt.DefaultText = message
	prompt.Filter = false
	prompt.KeyConfirm = keys.Enter
	prompt.KeySelect = keys.Space

	selectedOptions, err := prompt.Show()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	sort.Strings(selectedOptions)

	var result []string
	for _, option := range selectedOptions {
		result = append(result, items[option])
	}

	return result, nil
}

func Confirm(message string, defaultValue bool) (bool, error) {
	var confirmText, rejectText string
	if defaultValue {
		confirmText = "Y"
		rejectText = "n"
	} else {
		confirmText = "y"
		rejectText = "N"
	}
	res, err := pterm.InteractiveConfirmPrinter{
		DefaultValue: defaultValue,
		DefaultText:  message,
		TextStyle:    &pterm.ThemeDefault.PrimaryStyle,
		ConfirmText:  confirmText,
		ConfirmStyle: &pterm.ThemeDefault.PrimaryStyle,
		RejectText:   rejectText,
		RejectStyle:  &pterm.ThemeDefault.PrimaryStyle,
		SuffixStyle:  &pterm.ThemeDefault.SecondaryStyle,
	}.Show()
	return res, errors.WithStack(err)
}

func Input(message string) (string, error) {
	input := pterm.DefaultInteractiveTextInput.WithDefaultText(message)
	result, err := input.Show()
	if err != nil {
		return "", errors.WithStack(err)
	}
	return result, nil
}

func ReadSecret(message string, file *os.File) (string, error) {
	log.Info(message)
	// TODO: print * characters instead of the actual secret
	secret, err := term.ReadPassword(int(file.Fd()))
	if err != nil {
		return "", errors.WithStack(err)
	}
	return string(secret), nil
}
