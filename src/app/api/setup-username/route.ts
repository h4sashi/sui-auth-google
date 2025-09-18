// src/app/api/setup-username/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { createServerSupabaseClient } from '@/lib/supabase'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { walletAddress, username } = body

    if (!walletAddress || !username) {
      return NextResponse.json({
        success: false,
        error: 'Wallet address and username are required'
      }, { status: 400 })
    }

    const trimmedUsername = username.trim()

    if (trimmedUsername.length < 3 || trimmedUsername.length > 20) {
      return NextResponse.json({
        success: false,
        error: 'Username must be between 3 and 20 characters'
      }, { status: 400 })
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(trimmedUsername)) {
      return NextResponse.json({
        success: false,
        error: 'Username can only contain letters, numbers, underscore, and hyphen'
      }, { status: 400 })
    }

    const supabase = createServerSupabaseClient()

    // Check if username is already taken
    const { data: existingUser } = await supabase
      .from('user_profiles')
      .select('id')
      .eq('name', trimmedUsername)
      .neq('sui_address', walletAddress)
      .single()

    if (existingUser) {
      return NextResponse.json({
        success: false,
        error: 'Username already taken'
      }, { status: 400 })
    }

    // Update username
    const { data: updatedProfile, error: updateError } = await supabase
      .from('user_profiles')
      .update({ 
        name: trimmedUsername,
        updated_at: new Date().toISOString()
      })
      .eq('sui_address', walletAddress)
      .select()
      .single()

    if (updateError) {
      console.error('Username update error:', updateError)
      return NextResponse.json({
        success: false,
        error: 'Failed to update username'
      }, { status: 500 })
    }

    return NextResponse.json({
      success: true,
      message: 'Username updated successfully',
      profile: {
        id: updatedProfile.id,
        name: updatedProfile.name,
        suiWallet: updatedProfile.sui_address,
        authMethod: updatedProfile.auth_method,
        profileId: updatedProfile.id,
        needsUsernameSetup: false
      }
    })

  } catch (err) {
    const error = err as Error
    console.error('Username setup error:', error)
    return NextResponse.json({
      success: false,
      error: 'Username setup failed: ' + error.message
    }, { status: 500 })
  }
}