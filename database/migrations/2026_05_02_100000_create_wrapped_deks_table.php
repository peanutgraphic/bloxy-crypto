<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('wrapped_deks', function (Blueprint $table) {
            $table->id();
            $table->string('owner_user_type', 191);
            $table->string('owner_user_id', 36);
            $table->string('subject_type', 191);
            $table->string('subject_id', 36);
            // Nullable: a NULL passkey_id row is the recovery-key-wrapped variant.
            $table->unsignedBigInteger('passkey_id')->nullable();
            // Wrapped DEK as base64url text. ~50-80 bytes typical.
            $table->text('wrapped_dek_text');
            $table->timestamps();

            $table->index(['owner_user_type', 'owner_user_id'], 'wd_owner_idx');
            $table->index(['subject_type', 'subject_id'], 'wd_subject_idx');
            $table->index('passkey_id', 'wd_passkey_idx');
            $table->index(['owner_user_type', 'owner_user_id', 'passkey_id'], 'wd_owner_passkey_idx');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('wrapped_deks');
    }
};
