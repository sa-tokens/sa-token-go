// @Author daixk 2025/12/12 11:56:00
package adapter

type Pool interface {
	Submit(task func()) error
	Stop()
	Stats() (running, capacity int, usage float64)
}
