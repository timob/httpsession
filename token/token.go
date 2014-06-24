package token

type Token interface {
	String() string
	IsEmpty() bool
	Equal(Token) bool
}

type TokenStr string

func (t TokenStr) String() string {
	return string(t)
}

func (t TokenStr) IsEmpty() bool {
	return false
}

func (t TokenStr) Equal(e Token) bool {
	return e.IsEmpty() == false && t.String() == e.String()
}

type emptyToken struct{}

func (e emptyToken) String() string {
	return ""
}

func (e emptyToken) IsEmpty() bool {
	return true
}

func (t emptyToken) Equal(e Token) bool {
	return e.IsEmpty()
}

var EmptyToken emptyToken
