package small_rational

type Vector []SmallRational

func (v Vector) MustSetRandom() {
	for i := range v {
		v[i].MustSetRandom()
	}
}
