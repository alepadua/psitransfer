<template lang="pug">
  .download-app
    a.btn.btn-sm.btn-info.btn-new-session(@click='newSession()', :title='$root.lang.newUpload')
      icon.fa-fw(name="cloud-upload-alt")
      span.hidden-xs  {{ $root.lang.newUpload }}
    .alert.alert-danger(v-show="error")
      strong
        icon.fa-fw(name="exclamation-triangle")
        |  {{ error }}

    .well.sso-card(v-if='ssoRequired')
      h3.text-primary
        icon.fa-fw(name="shield-alt")
        |  {{ $root.lang.highSecurityTransferTitle || 'High-Security Organization Transfer' }}
      p.lead(v-if="ssoOrgName") {{ ($root.lang.ssoNoticeMessage || 'To access files shared for {org}, please authenticate with your corporate account.').replace('{org}', ssoOrgName) }}
      p.alert.alert-info(v-if="ssoHasPassword")
        icon.fa-fw(name="key")
        |  {{ $root.lang.ssoDualAuthNotice || 'Note: This transfer requires SSO Authentication + Password Decryption.' }}
      p(style="margin-top: 15px;")
        a.btn.btn-lg.btn-primary(:href='ssoLoginUrl', @click="clearAutoRedirectTimer")
          icon.fa-fw(name="shield-alt")
          |  {{ ($root.lang.ssoSignInWith || 'Sign in with {org} SSO').replace('{org}', ssoOrgName) }}
      p.text-muted.small(v-if="autoRedirectSeconds > 0", style="margin-top: 10px;")
        | {{ ($root.lang.ssoAutoRedirecting || 'Redirecting to corporate SSO in {seconds} seconds...').replace('{seconds}', autoRedirectSeconds) }} 
        a(@click.prevent="clearAutoRedirectTimer", style="cursor: pointer; text-decoration: underline;") [Cancel]

    .alert.alert-danger(v-if='ssoDenied')
      strong
        icon.fa-fw(name="exclamation-triangle")
        |  {{ ssoMessage }}
      div(v-if="ssoUserEmail", style="margin-top: 10px;")
        p.small {{ $root.lang.ssoLoggedInAs || 'Currently signed in as' }}: <strong>{{ ssoUserEmail }}</strong> ({{ ssoUserOrg }})
        button.btn.btn-sm.btn-warning(@click="switchSsoAccount")
          icon.fa-fw(name="sign-out-alt")
          |  {{ $root.lang.ssoSwitchAccount || 'Switch SSO Account' }}

    .well(v-if='needsPassword && !ssoRequired && !ssoDenied')
      h3 {{ $root.lang.password }}
      .form-group
        input.form-control(type='password', v-model='password', @keyup.enter='password.length && fetchBucket()' autofocus)
      p.text-danger(v-show='passwordWrong')
        strong {{ $root.lang.accessDenied }}
      |
      button.decrypt.btn.btn-primary(:disabled='password.length<1', @click='fetchBucket()')
        icon.fa-fw(name="key")
        |  {{ $root.lang.decrypt }}
    .panel.panel-primary(v-if='!needsPassword && !loading')
      .panel-heading
        strong {{ $root.lang.files }}
        div.pull-right.btn-group.btn-download-archive(v-if="downloadsAvailable")
          a.btn.btn-sm.btn-default(
            @click="downloadAll('zip')"
            @keydown.enter.prevent="downloadAll('zip')"
            @keydown.space.prevent="downloadAll('zip')"
            :title="$root.lang.zipDownload"
            tabindex="0"
            role="button"
          )
            icon.fa-fw(name="download")
            |  zip
          a.btn.btn-sm.btn-default(
            @click="downloadAll('tar.gz')"
            @keydown.enter.prevent="downloadAll('tar.gz')"
            @keydown.space.prevent="downloadAll('tar.gz')"
            :title="$root.lang.tarGzDownload"
            tabindex="0"
            role="button"
          )
            icon.fa-fw(name="download")
            |  tar.gz
      .panel-body
        table.table.table-hover.table-striped.files
          tbody
            tr(
              v-for='file in files',
              style='cursor: pointer',
              @click='download(file)',
              @keydown.enter.prevent='download(file)',
              @keydown.space.prevent='download(file)',
              tabindex="0",
              role="button"
            )
              td.file-icon
                file-icon(:file='file')
              td
                div.pull-right.btn-group
                  clipboard.btn.btn-sm.btn-default(:value='baseURI + file.url', @change='copied(file, $event)', :title='$root.lang.copyToClipboard')
                    a
                      icon(name="copy")
                  a.btn.btn-sm.btn-default(:title="$root.lang.preview", @click.prevent.stop="preview=file", v-if="file.previewType")
                    icon(name="eye")
                i.pull-right.fa.fa-check.text-success.downloaded(v-show='file.downloaded')
                p
                  strong {{ file.metadata.name }}
                  small.file-size(v-if="isFinite(file.size)") ({{ humanFileSize(file.size) }})
                p {{ file.metadata.comment }}

    preview-modal(:preview="preview", :files="previewFiles", :max-size="config.maxPreviewSize", @close="preview=false")

</template>


<script>
  "use strict";

  import FileIcon from './common/FileIcon.vue';
  import Clipboard from './common/Clipboard.vue';
  import PreviewModal from './Download/PreviewModal.vue';

  import 'vue-awesome/icons/cloud-upload-alt';
  import 'vue-awesome/icons/exclamation-triangle';
  import 'vue-awesome/icons/copy';
  import 'vue-awesome/icons/check';
  import 'vue-awesome/icons/download';
  import 'vue-awesome/icons/key';
  import 'vue-awesome/icons/eye';
  import 'vue-awesome/icons/shield-alt';
  import 'vue-awesome/icons/sign-out-alt';

  function getPreviewType(file, maxSize) {
    if(!file || !file.metadata) return false;
    if(file.metadata.retention === 'one-time') return false;
    // no preview for files size > 2MB
    if(file.size > maxSize) return false;
    if(file.metadata.type && file.metadata.type.match(/^image\/.*/)) return 'image';
    else if(file.metadata.type && file.metadata.type.match(/(text\/|xml|json|javascript|x-sh)/)
      || file.metadata.name && file.metadata.name
        .match(/\.(jsx|vue|sh|pug|less|scss|sass|c|h|conf|log|bat|cmd|lua|class|java|py|php|yml|sql|md)$/)) {
      return 'text';
    }
    return false;
  }

  export default {
    name: 'app',
    components: { FileIcon, Clipboard, PreviewModal },
    data () {
      return {
        files: [],
        sid: document.location.pathname.match(/^.*\/([^\/?#]+)/)[1],
        baseURI: this.$root.baseURI,
        passwordWrong: false,
        needsPassword: false,
        loading: true,
        password: '',
        content: '',
        error: '',
        config: {},
        archiveToken: '',
        preview: false,
        ssoRequired: false,
        ssoDenied: false,
        ssoLoginUrl: '',
        ssoOrgName: '',
        ssoMessage: '',
        ssoHasPassword: false,
        ssoUserEmail: '',
        ssoUserOrg: '',
        ssoRequiredOrg: '',
        autoRedirectTimer: null,
        autoRedirectSeconds: 0,
      }
    },

    computed: {
      downloadsAvailable: function() {
        if (!this.archiveToken) return false;
        return this.files.filter(f => !f.downloaded || f.metadata.retention !== 'one-time').length > 0
      },
      previewFiles: function() {
        return this.files.filter(f => !!f.previewType);
      }

    },

    methods: {

      download(file) {
        if(file.downloaded && file.metadata.retention === 'one-time') {
          alert(this.$root.lang.oneTimeDownloadExpired);
          return;
        }
        const aEl = document.createElement('a');
        aEl.setAttribute('href', file.url);
        aEl.setAttribute('download', file.metadata.name);
        aEl.style.display = 'none';
        document.body.appendChild(aEl);
        aEl.click();
        document.body.removeChild(aEl);
        file.downloaded = true;
      },

      async downloadAll(format) {
        let token = this.archiveToken;
        if (!token) {
          console.error('Archive token not found.');
          return;
        }
        document.location.href = this.$root.baseURI
          + '/files/' + this.sid + '++'
          + this.archiveToken + '.' + format;
        this.files.forEach(f => { f.downloaded = true; })
      },

      copied(file, $event) {
        file.downloaded = $event === 'copied';
      },

      humanFileSize(fileSizeInBytes) {
        let i = -1;
        const byteUnits = [' kB', ' MB', ' GB', ' TB', 'PB', 'EB', 'ZB', 'YB'];
        let size = fileSizeInBytes;
        do {
          size = size / 1024;
          i++;
        }
        while(size > 1024);
        return Math.max(size, 0.01).toFixed(2) + byteUnits[i];
      },

      newSession() {
        document.location.href = this.$root.baseURI;
      },

      isFinite(value) {
        if(typeof value !== 'number') return false;
        return !(value !== value || value === Infinity || value === -Infinity);
      },

      switchSsoAccount() {
        document.location.href = this.baseURI + 'auth/sso/logout?returnTo=' + encodeURIComponent(document.location.pathname);
      },

      clearAutoRedirectTimer() {
        if (this.autoRedirectTimer) {
          clearInterval(this.autoRedirectTimer);
          this.autoRedirectTimer = null;
        }
        this.autoRedirectSeconds = 0;
      },

      startAutoRedirect() {
        this.autoRedirectSeconds = 4;
        this.autoRedirectTimer = setInterval(() => {
          this.autoRedirectSeconds--;
          if (this.autoRedirectSeconds <= 0) {
            this.clearAutoRedirectTimer();
            if (this.ssoLoginUrl) {
              document.location.href = this.ssoLoginUrl;
            }
          }
        }, 1000);
      },

      fetchBucket() {
        const xhr = new XMLHttpRequest();
        xhr.open('GET', this.sid + '.json');
        if(this.password) {
          xhr.setRequestHeader('x-download-pass', this.password);
        }
        xhr.onload = () => {
          if (xhr.status === 200) {
            try {
              const data = JSON.parse(xhr.responseText);
              this.config = data.config;
              this.archiveToken = data.archiveToken || '';
              this.files = data.items.map(f => {
                return Object.assign(f, {
                  downloaded: false,
                  previewType: getPreviewType(f, this.config.maxPreviewSize)
                });
              });
              this.loading = false;
              this.needsPassword = false;
              this.ssoRequired = false;
              this.ssoDenied = false;
            }
            catch (e) {
              this.error = e.toString();
            }
          } else if (xhr.status === 401) {
            try {
              const resData = JSON.parse(xhr.responseText);
              if (resData.error === 'SSO_REQUIRED') {
                this.ssoRequired = true;
                this.ssoLoginUrl = resData.loginUrl;
                this.ssoOrgName = resData.orgName || resData.org;
                this.ssoMessage = resData.message;
                this.ssoHasPassword = !!resData.hasPassword;
                this.loading = false;
                this.startAutoRedirect();
                return;
              }
            } catch {
              // Not JSON SSO response
            }

            if(this.needsPassword) {
              this.passwordWrong = true;
            } else {
              this.needsPassword = true;
            }
            this.loading = false;
          } else if (xhr.status === 403) {
            try {
              const resData = JSON.parse(xhr.responseText);
              if (resData.error === 'ORG_DENIED') {
                this.ssoDenied = true;
                this.ssoMessage = resData.message;
                this.ssoUserEmail = resData.userEmail || '';
                this.ssoUserOrg = resData.userOrg || '';
                this.ssoRequiredOrg = resData.requiredOrg || '';
                this.loading = false;
                return;
              }
            } catch {
              // Not JSON SSO response
            }
            this.error = `${ xhr.status } ${ xhr.statusText }: ${ xhr.responseText }`;
            this.loading = false;
          } else {
            this.error = `${ xhr.status } ${ xhr.statusText }: ${ xhr.responseText }`;
            this.loading = false;
          }
        };
        xhr.send();
      },
    },

    beforeMount() {
      this.fetchBucket();
    },

    beforeDestroy() {
      this.clearAutoRedirectTimer();
    }
  }
</script>
