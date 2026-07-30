<template lang="pug">
  div(v-if="config && config.retentions")
    .panel.panel-default(:class="{'panel-info': !disabled}")
      .panel-heading
        strong {{ $root.lang.settings }}
      .panel-body
        .form-group(v-if="config && config.ssoEnabled && config.availableOrgs && config.availableOrgs.length")
          label {{ $root.lang.transferMode || 'Transfer Security' }}
          .radio
            label
              input(
                type="radio"
                name="orgMode"
                value="standard"
                :checked="!isOrgMode"
                @change="setOrgMode('standard')"
                :disabled="disabled"
              )
              |  {{ $root.lang.standardTransfer || 'Standard Transfer (Public / Password Only)' }}
          .radio
            label
              input(
                type="radio"
                name="orgMode"
                value="org"
                :checked="isOrgMode"
                @change="setOrgMode('org')"
                :disabled="disabled"
              )
              |  {{ $root.lang.orgTransfer || 'Secure Organization Transfer (SSO Required)' }}
          .form-group(v-if="isOrgMode", style="margin-top: 10px;")
            label(for="orgSelect") {{ $root.lang.selectOrg || 'Select Target Organization' }}
            select#orgSelect.form-control(
              :value="selectedOrg"
              @change="$store.commit('upload/ORG', $event.target.value)"
              :disabled="disabled"
            )
              option(
                v-for="orgItem in config.availableOrgs"
                :value="orgItem.domain"
                :selected="orgItem.domain === selectedOrg"
              ) {{ orgItem.name }} ({{ orgItem.domain }})

        .form-group
          label(for='retention') {{ $root.lang.retention }}
          |
          select#retention.form-control(:value='retention', :disabled='disabled',
          @change="$store.commit('upload/RETENTION', $event.target.value)")
            option(
              v-for='(label, seconds) in config.retentions'
              :value="seconds"
              :selected="seconds === retention"
            ) {{ $root.lang.retentions[seconds] || label }}
        div
          label(for='password') {{ $root.lang.password }}
          .input-group(:class="{'has-error': config.requireBucketPassword && !password}")
            input#password.form-control(
              type='text'
              :value='password'
              @input="$store.commit('upload/PASSWORD', $event.target.value)"
              :disabled='disabled'
              :placeholder="config.requireBucketPassword ? $root.lang.required : $root.lang.optional"
              required="config.requireBucketPassword"
            )
            span.input-group-addon(
              style='cursor: pointer'
              :title='$root.lang.generateRandomPassword'
              @click='generatePassword()'
              tabindex="0"
              role="button"
              @keydown.enter.prevent='generatePassword()'
              @keydown.space.prevent='generatePassword()'
            )
              icon(name="key")
</template>

<script type="text/babel">
  import { mapState } from 'vuex';
  import 'vue-awesome/icons/key';

  const passGen = {
    _pattern: /[A-Z0-9_\-+!]/,
    _getRandomByte: function() {
      const result = new Uint8Array(1);
      let fixedcrypto = window.msCrypto;
      if (!fixedcrypto) {
        fixedcrypto = window.crypto;
      }
      fixedcrypto.getRandomValues(result);
      return result[0];
    },
    generate: function(length) {
      let fixedcrypto2 = window.msCrypto;
      if (!fixedcrypto2) {
        fixedcrypto2 = window.crypto;
      }
      if (!fixedcrypto2 || !fixedcrypto2.getRandomValues) return '';
      return Array.apply(null, { 'length': length }).map(function() {
        let result;
        while (true) {
          result = String.fromCharCode(this._getRandomByte());
          if (this._pattern.test(result)) return result;
        }
      }, this).join('');
    }
  };

  export default {
    name: 'Settings',

    data() {
      return {
        isOrgMode: false,
      };
    },

    computed: mapState({
      config: 'config',
      disabled: 'disabled',
      retention: state => state.upload.retention,
      password: state => state.upload.password,
      selectedOrg: state => state.upload.org,
    }),

    methods: {
      generatePassword() {
        if (this.disabled) return;
        this.$store.commit('upload/PASSWORD', passGen.generate(10));
      },
      setOrgMode(mode) {
        if (mode === 'standard') {
          this.isOrgMode = false;
          this.$store.commit('upload/ORG', '');
        } else {
          this.isOrgMode = true;
          if (this.config.availableOrgs && this.config.availableOrgs.length) {
            this.$store.commit('upload/ORG', this.config.availableOrgs[0].domain);
          }
        }
      }
    }
  };
</script>
