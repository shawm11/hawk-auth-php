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
     * Check PHP files for errors (including style errors)
     */
    public function lint()
    {
        return $this->taskExecStack()
                    ->stopOnFail()
                    ->exec('"./vendor/bin/phpcs"')
                    ->exec('"./vendor/bin/phpstan" analyse')
                    ->run();
    }

    /**
     * Bump the version and prepare for release
     */
    public function release()
    {
        $execution = $this->taskExecStack()
                          ->stopOnFail()
                          ->exec(
                              '"./vendor/bin/robo" git:stash "release-'
                              . (new \DateTime)->format(\DateTime::ISO8601) . '"'
                          )
                          ->exec('"./vendor/bin/robo" lint')
                          ->exec('"./vendor/bin/robo" test')
                          ->exec('"./vendor/bin/robo" git:stash-pop')
                          ->exec('standard-version')
                          ->run();

        if (!$execution->wasSuccessful()) {
            $this->io()->error('RELEASE FAILED!');
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
}
