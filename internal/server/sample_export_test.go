package server

// ResetSampleIndexForTest drops the in-memory index of samplings, as a restart does: the next sampling rebuilds it from the chain.
func (s *Server) ResetSampleIndexForTest() {
	s.sampleMu.Lock()
	s.sampled = nil
	s.sampleMu.Unlock()
}
