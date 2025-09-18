import WalletConnection from '@/components/WalletConnection'

export default function Home() {
  return (
    <main className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4">
      <div className="container mx-auto">
        <h1 className="text-4xl font-bold text-center mb-2 text-gray-800">
          Sui Wallet Connection
        </h1>
        <p className="text-center text-gray-600 mb-8">
          Connect your Sui wallet using Suiet Wallet Kit
        </p>
        
        <WalletConnection />
      </div>
    </main>
  )
}