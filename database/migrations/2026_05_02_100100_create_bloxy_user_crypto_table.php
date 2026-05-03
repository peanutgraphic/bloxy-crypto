<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('bloxy_user_crypto', function (Blueprint $table) {
            $table->id();
            $table->string('user_type', 191);
            $table->string('user_id', 36);
            // 32-byte salt for HKDF KEK derivation, base64url.
            $table->string('kek_hkdf_salt', 64);
            // 16-byte salt for Argon2id Recovery KEK derivation, base64url.
            $table->string('recovery_kek_salt', 32);
            // 16-byte salt for Argon2id recovery verifier hash, base64url.
            $table->string('recovery_verifier_salt', 32);
            // Argon2id verifier hash (16-byte hash, base64url; exact bytes
            // for constant-time compare).
            $table->string('recovery_verifier_hash', 32);
            $table->timestamps();

            $table->unique(['user_type', 'user_id'], 'buc_user_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('bloxy_user_crypto');
    }
};
