import { render, screen } from '@testing-library/react'
import App from './App'

describe('App', () => {
  it('renders the application title', () => {
    render(<App />)
    const titleElement = screen.getByText(/VulnChain CTF Framework/i)
    expect(titleElement).toBeInTheDocument()
  })

  it('renders the welcome message', () => {
    render(<App />)
    const welcomeElement = screen.getByText(/Welcome to VulnChain/i)
    expect(welcomeElement).toBeInTheDocument()
  })
})
