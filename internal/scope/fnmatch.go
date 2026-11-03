package scope

import "github.com/jfillman/clearance/internal/pycompat"

// FnmatchCase is Python's fnmatch.fnmatchcase(name, pat) (pycompat.FnmatchTranslate), through this cache.
func (c *Globs) FnmatchCase(name, pat string) bool {
	re := c.get(&c.fn, pat, func() string { return pycompat.FnmatchTranslate(pat) })
	return re.MatchString(name)
}
