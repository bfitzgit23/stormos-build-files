# Automated Build Pipeline for StormOS

## Proposal
Implement automated CI/CD pipelines to build StormOS ISOs on every commit, reducing manual build work and enabling faster iteration.

## Benefits
- Automated ISO builds on every push
- Consistent, reproducible builds
- Faster feedback on changes
- Free tier available on both GitHub and GitLab

---

## Option 1: GitHub Actions (Recommended)

### Setup Instructions
1. Go to your repository on GitHub
2. Click **Actions** tab
3. Click **New workflow**
4. Choose **set up a workflow yourself**

### Free Tier
- 2,000 minutes/month for private repos (free tier)
- Unlimited public repos
- Builds run on Ubuntu runners

### Files Included
- `.github/workflows/build.yml` - GitHub Actions workflow

### GitHub Actions Workflow
```yaml
name: Build StormOS ISO

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: archlinux/archlinux:latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install build dependencies
        run: |
          pacman -Sy --noconfirm archiso git

      - name: Build ISO
        run: |
          cd install-stormos-xfce
          ./build.sh -v

      - name: Upload ISO artifact
        uses: actions/upload-artifact@v4
        with:
          name: stormos-iso
          path: install-stormos-xfce/out/*.iso
          retention-days: 7
```

---

## Option 2: GitLab CI/CD

### Setup Instructions
1. Go to GitLab and create a new project
2. Import your GitHub repository or push directly
3. The `.gitlab-ci.yml` file will auto-detect

### Free Tier
- 400 minutes/month shared runners (free tier)
- Unlimited private repos
- Unlimited public repos

### Files Included
- `.gitlab-ci.yml` - GitLab CI/CD pipeline

---

## Option 3: Hybrid Approach (GitHub + GitLab Mirror)

Set up GitHub Actions as primary, mirror to GitLab for additional CI minutes:

```yaml
# In your GitHub Actions workflow
- name: Mirror to GitLab
  if: github.ref == 'refs/heads/main'
  uses: SvanBoxel/gitlab-mirror-workflow@master
  with:
    GITLAB_REPO: ${{ secrets.GITLAB_REPO }}
    GITLAB_TOKEN: ${{ secrets.GITLAB_TOKEN }}
```

---

## Cost Comparison

| Platform | Free Minutes | Private Repos | Public Repos |
|----------|-------------|---------------|--------------|
| GitHub Actions | 2,000/month | Yes | Unlimited |
| GitLab CI | 400/month | Unlimited | Unlimited |
| Combined | 2,400/month | Yes | Unlimited |

---

## Files Provided

| File | Purpose |
|------|---------|
| `.github/workflows/build.yml` | GitHub Actions workflow |
| `.gitlab-ci.yml` | GitLab CI/CD pipeline |

---

## Build Troubleshooting

If mkarchiso reports errors such as `target not found:  plymouth`, check `packages.x86_64` for package lines beginning with a space. Pacman treats the whitespace as part of the package name, so ` plymouth` is different from `plymouth`.

The package lists now contain one package name per line with no leading whitespace. To recover an old checkout, run this from the repository root:

```bash
sed -i 's/^[[:space:]]\+//' install-stormos-kde/packages.x86_64
sed -i 's/^[[:space:]]\+//' install-stormos-xfce/packages.x86_64
sudo rm -rf install-stormos-kde/work install-stormos-xfce/work
```

The message `cannot overwrite existing file` comes from Bash `noclobber`, not pacman. Edit the tracked files directly or use `tee` when intentionally replacing an existing file. Rebuild from the selected profile with `sudo ./build.sh -v`.

## Next Steps

1. Enable the workflow in GitHub Actions tab
2. Test the pipeline on a feature branch
3. Set up branch protection for main
4. Configure notifications for failed builds

Would you like me to create these files in the repository?
