<?php
// phpcs:disable PSR1.Classes.ClassDeclaration.MissingNamespace

use vierbergenlars\SemVer\version;

/**
 * This is project's console commands configuration for Robo task runner.
 *
 * @see http://robo.li/
 */
class RoboFile extends \Robo\Tasks
{
    private $composerJson;

    /**
     * Commit and tag the version bump (increment)
     */
    public function bumpCommit()
    {
        $version = $this->getComposerVersion()->getVersion();

        $this->taskGitStack()
             ->stopOnFail()
             ->add('.')
             ->commit("chore: bump to version $version", '--no-verify')
             ->tag("v$version")
             ->run();
    }

    /**
     * Increment the MAJOR version
     */
    public function bumpMajor()
    {
        $composerVersion = $this->getComposerVersion();
        $composerVersion->inc('major');
        $this->setComposerVersion($composerVersion);
    }

    /**
     * Increment the MINOR version
     */
    public function bumpMinor()
    {
        $composerVersion = $this->getComposerVersion();
        $composerVersion->inc('minor');
        $this->setComposerVersion($composerVersion);
    }

    /**
     * Increment the PATCH version
     */
    public function bumpPatch()
    {
        $composerVersion = $this->getComposerVersion();
        $composerVersion->inc('patch');
        $this->setComposerVersion($composerVersion);
    }

    /**
     * The command executed when the Git pre-commit hook is triggered
     */
    public function gitHookPreCommit()
    {
        $execution = $this->taskExecStack()
                          ->stopOnFail()
                          ->exec('"./vendor/bin/robo" git:stash "pre-commit-'
                            . (new \DateTime)->format(\DateTime::ISO8601) . '"')
                          ->exec('"./vendor/bin/robo" lint')
                          ->exec('"./vendor/bin/robo" test')
                          ->exec('"./vendor/bin/robo" git:stash-pop')
                          ->run();

        if (!$execution->wasSuccessful()) {
            $this->io()->error('ABORTING COMMIT!');
            $this->_exec('"./vendor/bin/robo" git:stash-pop');
        }

        return $execution;
    }

    /**
     * Push changes to the master branch of the remote repository
     */
    public function gitPushMaster()
    {
        return $this->_exec('git push origin master --tags');
    }

    /**
     * Stash the uncommitted changes away
     *
     * @param  $name  A name for the stash
     */
    public function gitStash($name)
    {
        return $this->_exec("git stash save --keep-index --include-untracked $name");
    }

    /**
     * Remove a single stashed state from the stash list and apply it on top of
     * the current working tree state
     */
    public function gitStashPop()
    {
        $this->_exec('git stash pop');

        return null;
    }

    /**
     * Check PHP files for style errors
     */
    public function lint()
    {
        return $this->_exec('"./vendor/bin/phpcs"');
    }

    /**
     * Bump the version and release to the remote repository master branch
     * (Alias of release:patch)
     */
    public function release()
    {
        return $this->releasePatch();
    }

    /**
     * Bump the MAJOR version and release to the remote repository master branch
     */
    public function releaseMajor()
    {
        $execution = $this->taskExecStack()
                          ->stopOnFail()
                          ->exec(
                              '"./vendor/bin/robo" git:stash "release-major-'
                              . (new \DateTime)->format(\DateTime::ISO8601) . '"'
                          )
                          ->exec('"./vendor/bin/robo" lint')
                          ->exec('"./vendor/bin/robo" test')
                          ->exec('"./vendor/bin/robo" git:stash-pop')
                          ->exec('"./vendor/bin/robo" bump:major')
                          ->exec('"./vendor/bin/robo" bump:commit')
                          ->exec('"./vendor/bin/robo" git:push-master')
                          ->run();

        if (!$execution->wasSuccessful()) {
            $this->io()->error('MAJOR RELEASE FAILED!');
            $this->_exec('"./vendor/bin/robo" git:stash-pop');
        }

        return $execution;
    }

    /**
     * Bump the MINOR version and release to the remote repository master branch
     */
    public function releaseMinor()
    {
        $execution = $this->taskExecStack()
                          ->stopOnFail()
                          ->exec(
                              '"./vendor/bin/robo" git:stash "release-major-'
                              . (new \DateTime)->format(\DateTime::ISO8601) . '"'
                          )
                          ->exec('"./vendor/bin/robo" lint')
                          ->exec('"./vendor/bin/robo" test')
                          ->exec('"./vendor/bin/robo" git:stash-pop')
                          ->exec('"./vendor/bin/robo" bump:minor')
                          ->exec('"./vendor/bin/robo" bump:commit')
                          ->exec('"./vendor/bin/robo" git:push-master')
                          ->run();

        if (!$execution->wasSuccessful()) {
            $this->io()->error('MINOR RELEASE FAILED!');
            $this->_exec('"./vendor/bin/robo" git:stash-pop');
        }

        return $execution;
    }

    /**
     * Bump the PATCH version and release to the remote repository master branch
     */
    public function releasePatch()
    {
        $execution = $this->taskExecStack()
                          ->stopOnFail()
                          ->exec(
                              '"./vendor/bin/robo" git:stash "release-major-'
                              . (new \DateTime)->format(\DateTime::ISO8601) . '"'
                          )
                          ->exec('"./vendor/bin/robo" lint')
                          ->exec('"./vendor/bin/robo" test')
                          ->exec('"./vendor/bin/robo" git:stash-pop')
                          ->exec('"./vendor/bin/robo" bump:patch')
                          ->exec('"./vendor/bin/robo" bump:commit')
                          ->exec('"./vendor/bin/robo" git:push-master')
                          ->run();

        if (!$execution->wasSuccessful()) {
            $this->io()->error('PATCH RELEASE FAILED!');
            $this->_exec('"./vendor/bin/robo" git:stash-pop');
        }

        return $execution;
    }

    /**
     * Run all tests
     */
    public function test()
    {
        return $this->_exec('"./vendor/bin/phpunit"');
    }

    /**
     * Get the project's version number stored in the composer.json file
     *
     * @return \vierbergenlars\SemVer\version
     */
    private function getComposerVersion()
    {
        $this->composerJson = json_decode(file_get_contents('composer.json'), true);

        return new version($this->composerJson['version'] ?? '0.0.0');
    }

    /**
     * Set the project's version number stored in the composer.json file
     *
     * @param  \vierbergenlars\SemVer\version  $semver
     */
    private function setComposerVersion($semver)
    {
        $this->composerJson['version'] = $semver->getVersion();
        file_put_contents(
            'composer.json',
            json_encode($this->composerJson, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );
    }
}
